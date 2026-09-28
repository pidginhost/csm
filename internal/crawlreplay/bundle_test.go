package crawlreplay

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strings"
	"testing"
)

const (
	bundleSiteA = "dom-00000a.example"
	bundleSiteB = "dom-00000b.example"
	bundleAcctA = "acct-00000a"
	bundleAcctB = "acct-00000b"
	periodFrom  = fixtureStart
	periodTo    = fixtureStart + 59
)

// bundleStages mutates a synthetic bundle at each point a real bundle can
// go wrong: the rows, the manifest derived from them, and the encoded files.
type bundleStages struct {
	rows     func(recs *[]Record, vol *[]Volume)
	manifest func(m *Manifest)
	files    func(records, volume *[]byte)
}

type bundleFiles struct {
	manifest        Manifest
	raw             []byte
	records, volume []byte
}

// buildBundle writes a two-site bundle the way the converter does: site A
// carries healthy traffic from minute 1 to 58 of the period, site B none.
func buildBundle(t testing.TB, st bundleStages) bundleFiles {
	t.Helper()
	s := NewSynth(bundleSiteA, 3)
	recs := s.Pool(Traffic{From: periodFrom + 1, To: periodTo - 1, PerMinute: 3, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 4)
	for i := range recs {
		recs[i].Account = bundleAcctA
		recs[i].Seq = int64(i + 1)
	}
	vol := volumeOf(recs)
	if st.rows != nil {
		st.rows(&recs, &vol)
	}
	var recBuf, volBuf bytes.Buffer
	for _, r := range recs {
		if err := WriteRow(&recBuf, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range vol {
		if err := WriteRow(&volBuf, v); err != nil {
			t.Fatal(err)
		}
	}
	m := Manifest{
		FormatVersion: ManifestVersion, StreamVersion: StreamVersion, IdentityVersion: 1,
		Tool:            ToolRevision{Revision: strings.Repeat("a", 40), GoVersion: "go-test"},
		SaltFingerprint: "0123456789ab",
		Period:          Span{From: periodFrom, To: periodTo},
		Inventory:       Digest{SHA256: strings.Repeat("1", 64), Bytes: 100},
		Inputs: []Input{
			{Site: bundleSiteA, Ordinal: 0, SHA256: strings.Repeat("2", 64), Bytes: 10, ContentSHA256: strings.Repeat("3", 64), ContentBytes: 10},
			{Site: bundleSiteB, Ordinal: 0, SHA256: strings.Repeat("4", 64), Bytes: 0, ContentSHA256: strings.Repeat("5", 64), ContentBytes: 0},
		},
		Outputs: []Output{outputOf("records", recBuf.Bytes(), int64(len(recs))), outputOf("volume", volBuf.Bytes(), int64(len(vol)))},
		Sites:   []SiteManifest{siteOf(bundleSiteA, bundleAcctA, recs, vol), siteOf(bundleSiteB, bundleAcctB, recs, vol)},
	}
	m.Identities = identitiesOf(m.Sites, recs)
	m.Inputs[0].ContentBytes, m.Inputs[1].ContentBytes = m.Sites[0].Bytes, m.Sites[1].Bytes
	for i := range m.Inputs {
		if extent := m.Sites[i].Extent; extent != nil {
			copy := *extent
			m.Inputs[i].Extent = &copy
		}
		m.Inputs[i].DisorderSeconds = disorderOf(recs, m.Inputs[i].Site)
	}
	if st.manifest != nil {
		st.manifest(&m)
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := bundleFiles{manifest: m, raw: append(raw, '\n'), records: recBuf.Bytes(), volume: volBuf.Bytes()}
	if st.files != nil {
		st.files(&f.records, &f.volume)
	}
	return f
}

// disorderOf is the most a record's time trails an earlier record's time
// in the site's single input, as the converter measures it.
func disorderOf(recs []Record, site string) int64 {
	var latest, disorder int64
	for _, r := range recs {
		if r.Site != site {
			continue
		}
		if r.T < latest {
			disorder = max(disorder, latest-r.T)
		} else {
			latest = r.T
		}
	}
	return disorder
}

// syntheticIdentity pads a pseudonym's hexadecimal part into a digest.
func syntheticIdentity(pseudonym string) Identity {
	hexPart := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(pseudonym, ".example"), "dom-"), "acct-"), "e-")
	return Identity{Pseudonym: pseudonym, Digest: hexPart + strings.Repeat("f", 64-len(hexPart))}
}

// identitiesOf lists the sites, accounts and record episodes of a bundle,
// ordered by pseudonym, as the converter declares them.
func identitiesOf(sites []SiteManifest, recs []Record) []Identity {
	names := map[string]bool{}
	for _, s := range sites {
		names[s.Site], names[s.Account] = true, true
	}
	for _, r := range recs {
		if r.Episode != "" {
			names[r.Episode] = true
		}
	}
	out := []Identity{}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		out = append(out, syntheticIdentity(name))
	}
	return out
}

func volumeOf(recs []Record) []Volume {
	type siteMinute struct {
		site   string
		minute int64
	}
	var out []Volume
	index := map[siteMinute]int{}
	for _, r := range recs {
		key := siteMinute{r.Site, r.T / 60}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, Volume{Site: r.Site, Minute: r.T / 60})
		}
		out[i].Lines++
		out[i].Bytes += 100
		if r.Binding == "" {
			out[i].NoBinding++
		}
	}
	return out
}

func outputOf(kind string, data []byte, rows int64) Output {
	sum := sha256.Sum256(data)
	return Output{Kind: kind, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data)), Rows: rows}
}

// siteOf derives one site's manifest entry from the rows it owns.
func siteOf(site, account string, recs []Record, vol []Volume) SiteManifest {
	sm := SiteManifest{Site: site, Account: account, Labels: map[string]int64{}, Untimed: []UntimedLoss{}}
	for _, r := range recs {
		if r.Site != site {
			continue
		}
		sm.Records++
		sm.Labels[r.Label]++
		if r.Binding == "" {
			sm.AttributionLoss++
		}
		if r.Infra {
			sm.Infrastructure++
		}
		m := r.T / 60
		if sm.Extent == nil {
			sm.Extent = &Span{From: m, To: m}
		}
		sm.Extent.From, sm.Extent.To = min(sm.Extent.From, m), max(sm.Extent.To, m)
	}
	for _, v := range vol {
		if v.Site == site {
			sm.Bytes += v.Bytes
			sm.NoTarget += v.NoTarget
		}
	}
	sm.Lines = sm.Records
	return sm
}

// addUntimed records untimed lost lines the way the converter does, keeping
// site A's line and byte totals consistent with its input.
func addUntimed(m *Manifest, u UntimedLoss, bytesPerLine int64) {
	sm := &m.Sites[0]
	sm.Untimed = append(sm.Untimed, u)
	sm.Lines += u.Lines
	sm.Bytes += u.Lines * bytesPerLine
	sm.UnplacedBytes += u.Lines * bytesPerLine
	m.Inputs[0].ContentBytes += u.Lines * bytesPerLine
	switch u.Category {
	case LossOversized:
		sm.Oversized += u.Lines
	case LossRejected:
		sm.Rejected += u.Lines
	case LossTimeInvalid:
		sm.TimeInvalid += u.Lines
	case LossTimeFuture:
		sm.TimeFuture += u.Lines
	case LossIncomplete:
		sm.Incomplete += u.Lines
	}
}

// validateFiles runs the bundle through the same path crawl-calibrate uses.
func validateFiles(f bundleFiles, proof *CoverageProof) ([]BundleSite, []Record, error) {
	m, err := DecodeManifest(f.raw)
	if err != nil {
		return nil, nil, err
	}
	var seen []Record
	sites, err := ValidateBundle(BundleInput{Manifest: m, Proof: proof, Volume: bytes.NewReader(f.volume), Records: bytes.NewReader(f.records)}, 1,
		BundleVisitor{Record: func(r Record) error { seen = append(seen, r); return nil }})
	return sites, seen, err
}

func TestBundleBotProofRequiresEvidence(t *testing.T) {
	for _, proof := range []string{BotProofRange, BotProofDNS, BotProofNegative} {
		t.Run(proof, func(t *testing.T) {
			for _, withEvidence := range []bool{false, true} {
				f := buildBundle(t, bundleStages{
					rows: func(recs *[]Record, _ *[]Volume) {
						(*recs)[0].Bot, (*recs)[0].BotProof = "googlebot", proof
					},
					manifest: func(m *Manifest) {
						if withEvidence {
							m.BotEvidence = &BotEvidenceRef{
								Digest:     Digest{SHA256: strings.Repeat("b", 64), Bytes: 100},
								D2Revision: strings.Repeat("c", 40), ConfigSHA256: strings.Repeat("d", 64),
							}
						}
					},
				})
				_, seen, err := validateFiles(f, nil)
				if withEvidence {
					if err != nil || int64(len(seen)) != f.manifest.Outputs[0].Rows || seen[0].BotProof != proof {
						t.Fatalf("referenced proof: rows=%d err=%v", len(seen), err)
					}
				} else if !errors.Is(err, ErrBundle) || len(seen) != 0 {
					t.Fatalf("proof without provenance: rows=%d err=%v", len(seen), err)
				}
			}
		})
	}
}

func TestDecodeManifestIsCanonical(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	m, err := DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(f.raw)
	if m.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %q, want the SHA-256 of the manifest bytes", m.Digest())
	}
	encoded, err := EncodeManifest(m)
	if err != nil || !bytes.Equal(encoded, f.raw) {
		t.Fatalf("EncodeManifest does not reproduce the decoded manifest: %v", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, f.raw); err != nil {
		t.Fatal(err)
	}
	version := []byte(fmt.Sprintf(`"format_version": %d,`, ManifestVersion))
	older := func(v int) []byte {
		return bytes.Replace(f.raw, version, []byte(fmt.Sprintf(`"format_version": %d,`, v)), 1)
	}
	for name, raw := range map[string][]byte{
		"unknown field":   bytes.Replace(f.raw, []byte(`"format_version"`), []byte(`"note": "x",`+"\n  "+`"format_version"`), 1),
		"duplicate key":   bytes.Replace(f.raw, version, append(append([]byte{}, version...), version...), 1),
		"null tool":       replaceTool(t, f.raw, "null"),
		"trailing value":  append(append([]byte{}, f.raw...), []byte("{}\n")...),
		"reformatted":     append(compact.Bytes(), '\n'),
		"case alias":      bytes.Replace(f.raw, []byte(`"format_version"`), []byte(`"Format_Version"`), 1),
		"version 1":       older(1),
		"version 2":       older(2),
		"null untimed":    bytes.Replace(f.raw, []byte(`"untimed": []`), []byte(`"untimed": null`), 1),
		"null identities": buildBundle(t, bundleStages{manifest: func(m *Manifest) { m.Identities = nil }}).raw,
	} {
		if !bytes.Contains(f.raw, []byte(`"untimed": []`)) || !bytes.Contains(f.raw, version) {
			t.Fatal("fixture manifest lost its empty untimed list or its format version")
		}
		if bytes.Equal(raw, f.raw) {
			t.Fatalf("%s: the edit did not change the manifest", name)
		}
		if _, err := DecodeManifest(raw); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: err = %v, want ErrManifest", name, err)
		} else if name == "null identities" && err.Error() != manifestError("identities").Error() {
			t.Errorf("%s: err = %v, want an identity validation error", name, err)
		}
	}
}

func replaceTool(t *testing.T, raw []byte, value string) []byte {
	t.Helper()
	start := bytes.Index(raw, []byte(`"tool": {`))
	end := bytes.Index(raw[start:], []byte("},"))
	if start < 0 || end < 0 {
		t.Fatal("fixture manifest has no tool object")
	}
	return append(append(append([]byte{}, raw[:start]...), []byte(`"tool": `+value)...), raw[start+end+1:]...)
}

func TestValidateBundleAcceptsEverySite(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	sites, seen, err := validateFiles(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != int(f.manifest.Sites[0].Records) || len(sites) != 2 {
		t.Fatalf("validated %d records and %d sites", len(seen), len(sites))
	}
	quiet := sites[1]
	if quiet.Site != bundleSiteB || quiet.Records != 0 || quiet.Extent != nil || quiet.Coverage != nil || quiet.Certified != nil {
		t.Fatalf("zero-record site = %+v, want preserved without coverage", quiet)
	}
}

func TestBundleContractRejectsMismatch(t *testing.T) {
	siteB := func(recs *[]Record, l2, l1 string) Record {
		last := (*recs)[len(*recs)-1]
		return Record{T: last.T, Seq: 1, Site: bundleSiteB, Account: bundleAcctB, Binding: last.Binding,
			Class: ClassExpensive, L2: l2, L1: l1, Status: 200, Label: LabelHealthy}
	}
	gz := gzipBytes(t, buildBundle(t, bundleStages{}).records)
	truncated := func(records, _ *[]byte) { *records = gz[:len(gz)-8] }
	for name, tc := range map[string]struct {
		st   bundleStages
		want error
	}{
		"identity version": {bundleStages{manifest: func(m *Manifest) { m.IdentityVersion = 2 }}, ErrManifest},
		"stream version":   {bundleStages{manifest: func(m *Manifest) { m.StreamVersion = StreamVersion + 1 }}, ErrManifest},
		"manifest version": {bundleStages{manifest: func(m *Manifest) { m.FormatVersion = 1 }}, ErrManifest},
		"dirty tool":       {bundleStages{manifest: func(m *Manifest) { m.Tool.Dirty = true }}, ErrManifest},
		"unknown tool":     {bundleStages{manifest: func(m *Manifest) { m.Tool.Revision = "" }}, ErrManifest},
		"duplicate site":   {bundleStages{manifest: func(m *Manifest) { m.Sites = append(m.Sites, m.Sites[0]) }}, ErrManifest},
		"raw site name":    {bundleStages{manifest: func(m *Manifest) { m.Sites[1].Site = "customer.example" }}, ErrManifest},
		"duplicate output": {bundleStages{manifest: func(m *Manifest) { m.Outputs[1].Kind = "records" }}, ErrManifest},
		"missing output":   {bundleStages{manifest: func(m *Manifest) { m.Outputs = m.Outputs[:1] }}, ErrManifest},
		"category total":   {bundleStages{manifest: func(m *Manifest) { m.Sites[0].Lines++ }}, ErrManifest},
		"untimed total": {bundleStages{manifest: func(m *Manifest) {
			m.Sites[0].Untimed = append(m.Sites[0].Untimed, UntimedLoss{Category: LossOversized, Lines: 1})
		}}, ErrManifest},
		"label total": {bundleStages{manifest: func(m *Manifest) { m.Sites[0].Labels[LabelAttack] = 1 }}, ErrManifest},
		"duplicate content": {bundleStages{manifest: func(m *Manifest) {
			m.Inputs[1].ContentBytes = 10
			m.Inputs[1].ContentSHA256 = m.Inputs[0].ContentSHA256
		}}, ErrManifest},
		"input ordinal":     {bundleStages{manifest: func(m *Manifest) { m.Inputs[0].Ordinal = 1 }}, ErrManifest},
		"negative disorder": {bundleStages{manifest: func(m *Manifest) { m.Inputs[0].DisorderSeconds = -1 }}, ErrManifest},
		"disorder understated": {bundleStages{manifest: func(m *Manifest) {
			m.Inputs[0].DisorderSeconds = 0
		}}, ErrBundle},
		"extent past period": {bundleStages{manifest: func(m *Manifest) { m.Sites[0].Extent.To = periodTo + 1 }}, ErrManifest},
		"bad sha":            {bundleStages{manifest: func(m *Manifest) { m.Outputs[0].SHA256 = strings.Repeat("0", 64) }}, ErrBundle},
		"bad bytes":          {bundleStages{manifest: func(m *Manifest) { m.Outputs[1].Bytes++ }}, ErrBundle},
		"bad rows":           {bundleStages{manifest: func(m *Manifest) { m.Outputs[0].Rows++ }}, ErrBundle},
		"record total":       {bundleStages{manifest: func(m *Manifest) { m.Sites[0].Records--; m.Sites[0].Lines--; m.Sites[0].Labels[LabelHealthy]-- }}, ErrBundle},
		"byte total":         {bundleStages{manifest: func(m *Manifest) { m.Sites[0].Bytes++; m.Inputs[0].ContentBytes++ }}, ErrBundle},
		"content total":      {bundleStages{manifest: func(m *Manifest) { m.Inputs[0].ContentBytes++ }}, ErrManifest},
		"label mix": {bundleStages{manifest: func(m *Manifest) {
			m.Sites[0].Labels[LabelHealthy]--
			m.Sites[0].Labels[""] = 1
		}}, ErrBundle},
		"volume outside extent": {bundleStages{manifest: func(m *Manifest) { m.Sites[0].Extent.To-- }}, ErrBundle},
		"record outside extent": {bundleStages{
			rows: func(_ *[]Record, vol *[]Volume) { *vol = (*vol)[:len(*vol)-1] },
			manifest: func(m *Manifest) {
				m.Sites[0].Extent.To--
				m.Sites[0].Bytes -= 300
				m.Inputs[0].ContentBytes -= 300
			},
		}, ErrBundle},
		"unknown record site": {bundleStages{rows: func(recs *[]Record, _ *[]Volume) { (*recs)[3].Site = "dom-ffffff.example" }}, ErrBundle},
		"unknown volume site": {bundleStages{rows: func(_ *[]Record, vol *[]Volume) {
			*vol = append(*vol, Volume{Site: "dom-ffffff.example", Minute: periodFrom, Lines: 1, Bytes: 100})
		}}, ErrBundle},
		"duplicate volume row": {bundleStages{rows: func(_ *[]Record, vol *[]Volume) { *vol = append(*vol, (*vol)[0]) }}, ErrBundle},
		"volume moved": {bundleStages{rows: func(_ *[]Record, vol *[]Volume) {
			(*vol)[0].Lines--
			(*vol)[1].Lines++
		}}, ErrBundle},
		"account":       {bundleStages{rows: func(recs *[]Record, _ *[]Volume) { (*recs)[2].Account = bundleAcctB }}, ErrBundle},
		"l1 two parent": {bundleStages{rows: func(recs *[]Record, _ *[]Volume) { (*recs)[1].L2 = SynthKey(9) }}, ErrBundle},
		"l2 two sites": {bundleStages{rows: func(recs *[]Record, vol *[]Volume) {
			*recs = append(*recs, siteB(recs, SynthKey(1), SynthKey(7)))
			*vol = volumeOf(*recs)
		}}, ErrBundle},
		"site split": {bundleStages{rows: func(recs *[]Record, vol *[]Volume) {
			b := siteB(recs, SynthKey(5), SynthKey(6))
			*recs = append(append(append([]Record{}, (*recs)[:5]...), b), (*recs)[5:]...)
			*vol = volumeOf(*recs)
		}}, ErrBundle},
		"sequence beyond total lines": {bundleStages{rows: func(recs *[]Record, _ *[]Volume) { (*recs)[len(*recs)-1].Seq += 1000 }}, ErrBundle},
		"repeated sequence":           {bundleStages{rows: func(recs *[]Record, _ *[]Volume) { (*recs)[1].Seq = (*recs)[0].Seq }}, ErrBundle},
		"file past inputs":            {bundleStages{rows: func(recs *[]Record, _ *[]Volume) { (*recs)[0].File = 1 }}, ErrBundle},
		"truncated gzip":              {bundleStages{files: truncated}, ErrDecode},
	} {
		t.Run(name, func(t *testing.T) {
			f := buildBundle(t, tc.st)
			_, _, err := validateFiles(f, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func countRecords(rows *int64) func(io.Reader) error {
	return func(r io.Reader) error {
		return ReadRecords(r, func(Record) error { *rows++; return nil })
	}
}

func TestReadBundleFileHashesWhatItReads(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	gz := gzipBytes(t, f.records)
	for name, data := range map[string][]byte{"plain": f.records, "gzip": gz} {
		var rows int64
		d, err := ReadBundleFile(bytes.NewReader(data), countRecords(&rows))
		sum := sha256.Sum256(data)
		if err != nil || d.SHA256 != hex.EncodeToString(sum[:]) || d.Bytes != int64(len(data)) || rows != f.manifest.Sites[0].Records {
			t.Fatalf("%s: digest %+v rows %d err %v", name, d, rows, err)
		}
	}
	trailing := append(append([]byte{}, gz...), "junk"...)
	if _, err := ReadBundleFile(bytes.NewReader(trailing), countRecords(new(int64))); err == nil {
		t.Fatal("bytes after the gzip stream were accepted")
	}
	if _, err := ReadBundleFile(bytes.NewReader(f.records), func(io.Reader) error { return nil }); !errors.Is(err, ErrBundle) {
		t.Fatalf("unread content: err = %v, want ErrBundle", err)
	}
	// bufio reports a read error once and clears it; a retried read must
	// not turn a failed file into an apparently complete one.
	flaky := &failOnce{r: bytes.NewReader(f.records)}
	if _, err := ReadBundleFile(flaky, countRecords(new(int64))); !errors.Is(err, ErrBundle) {
		t.Fatalf("transient read error: err = %v, want ErrBundle", err)
	}
}

func TestBundleObservedExtents(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"site begins early":           func(m *Manifest) { m.Sites[0].Extent.From-- },
		"site ends late":              func(m *Manifest) { m.Sites[0].Extent.To++ },
		"missing input extent":        func(m *Manifest) { m.Inputs[0].Extent = nil },
		"input excludes first record": func(m *Manifest) { m.Inputs[0].Extent.From++ },
		"input excludes last record":  func(m *Manifest) { m.Inputs[0].Extent.To-- },
		"input begins early":          func(m *Manifest) { m.Inputs[0].Extent.From-- },
		"input ends late":             func(m *Manifest) { m.Inputs[0].Extent.To++ },
		"empty input claims records": func(m *Manifest) {
			m.Inputs[1].Extent = &Span{From: periodFrom, To: periodTo}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := buildBundle(t, bundleStages{manifest: mutate})
			if _, _, err := validateFiles(f, nil); !errors.Is(err, ErrBundle) {
				t.Fatalf("inconsistent observed extent: %v, want ErrBundle", err)
			}
		})
	}
}

func TestBundleExtentsAcrossInputs(t *testing.T) {
	st := bundleStages{
		rows: func(recs *[]Record, _ *[]Volume) {
			for i := len(*recs) / 2; i < len(*recs); i++ {
				(*recs)[i].File = 1
			}
		},
		manifest: func(m *Manifest) {
			first := &m.Inputs[0]
			second := *first
			first.ContentBytes /= 2
			first.Extent.To = periodFrom + 29
			second.Ordinal = 1
			second.ContentSHA256 = strings.Repeat("6", 64)
			second.ContentBytes = first.ContentBytes
			second.Extent = &Span{From: periodFrom + 30, To: periodTo - 1}
			m.Inputs = append(m.Inputs, second)
		},
	}
	f := buildBundle(t, st)
	if _, _, err := validateFiles(f, nil); err != nil {
		t.Fatalf("valid distinct input extents: %v", err)
	}
	setInputs := st.manifest
	st.manifest = func(m *Manifest) {
		setInputs(m)
		m.Inputs[0].Extent, m.Inputs[2].Extent = m.Inputs[2].Extent, m.Inputs[0].Extent
	}
	f = buildBundle(t, st)
	if _, _, err := validateFiles(f, nil); !errors.Is(err, ErrBundle) {
		t.Fatalf("records assigned to the wrong input: %v, want ErrBundle", err)
	}
}

func TestBundleRejectsChangedManifest(t *testing.T) {
	f := buildBundle(t, bundleStages{manifest: func(m *Manifest) {
		addUntimed(m, UntimedLoss{Category: LossRejected, Lines: 1}, 100)
	}})
	for name, mutate := range map[string]func(*Manifest){
		"provenance": func(m *Manifest) { m.SaltFingerprint = "ffffffffffff" },
		"loss bracket": func(m *Manifest) {
			m.Sites[0].Untimed[0].After = (periodTo + 2) * 60
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := DecodeManifest(f.raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&m)
			callbacks := 0
			_, err = ValidateBundle(BundleInput{Manifest: m, Proof: wholeProof(t, f),
				Volume: bytes.NewReader(f.volume), Records: bytes.NewReader(f.records)}, 1,
				BundleVisitor{Volume: func(Volume) error { callbacks++; return nil }})
			if !errors.Is(err, ErrManifest) || callbacks != 0 {
				t.Fatalf("changed manifest: %v, callbacks %d; want ErrManifest before callbacks", err, callbacks)
			}
		})
	}
}

func TestManifestLineByteAccounting(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"lines without bytes": func(m *Manifest) {
			addUntimed(m, UntimedLoss{Category: LossRejected, Lines: math.MaxInt64 - m.Sites[0].Lines}, 0)
		},
		"unplaced lines without bytes": func(m *Manifest) {
			addUntimed(m, UntimedLoss{Category: LossRejected, Lines: 1}, 0)
		},
		"unplaced bytes without lines": func(m *Manifest) {
			m.Sites[0].Bytes++
			m.Sites[0].UnplacedBytes++
			m.Inputs[0].ContentBytes++
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := buildBundle(t, bundleStages{manifest: mutate})
			if _, err := DecodeManifest(f.raw); !errors.Is(err, ErrManifest) {
				t.Fatalf("impossible byte accounting: %v, want ErrManifest", err)
			}
		})
	}
}

func TestManifestDisorderIncludesLossBrackets(t *testing.T) {
	const bound = int64(60)
	const at = (periodFrom + 20) * 60
	for name, tc := range map[string]struct {
		after, before int64
		invalid       bool
	}{
		"forward":               {at, at + bound + 1, false},
		"equal bound":           {at, at - bound, false},
		"understated":           {at, at - bound - 1, true},
		"outside period":        {at - 3600, at - 3600 - bound - 1, true},
		"open start":            {0, at, false},
		"open end":              {at, 0, false},
		"no timed neighbours":   {0, 0, false},
		"large valid timestamp": {math.MaxInt64, math.MaxInt64 - bound, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := buildBundle(t, bundleStages{manifest: func(m *Manifest) {
				m.Inputs[0].DisorderSeconds = bound
				addUntimed(m, UntimedLoss{Category: LossRejected, After: tc.after, Before: tc.before, Lines: 1}, 100)
			}})
			_, err := DecodeManifest(f.raw)
			if tc.invalid {
				if !errors.Is(err, ErrManifest) {
					t.Fatalf("loss bracket contradicts input disorder: %v, want ErrManifest", err)
				}
			} else if err != nil {
				t.Fatalf("consistent disorder refused: %v", err)
			}
		})
	}
}

type failOnce struct {
	r      io.Reader
	failed bool
}

func (f *failOnce) Read(p []byte) (int, error) {
	if !f.failed {
		f.failed = true
		return 0, errors.New("transient failure")
	}
	return f.r.Read(p)
}

func TestManifestIdentityDigests(t *testing.T) {
	const episode = "e-00000000000000e1"
	withEpisode := func(recs *[]Record, _ *[]Volume) {
		(*recs)[0].Label, (*recs)[0].Episode = LabelAttack, episode
	}
	f := buildBundle(t, bundleStages{rows: withEpisode})
	if _, _, err := validateFiles(f, nil); err != nil {
		t.Fatalf("declared identities refused: %v", err)
	}
	for name, tc := range map[string]struct {
		st   bundleStages
		want error
	}{
		"site not declared": {bundleStages{manifest: func(m *Manifest) {
			m.Identities = slices.DeleteFunc(m.Identities, func(id Identity) bool { return id.Pseudonym == bundleSiteB })
		}}, ErrManifest},
		"account not declared": {bundleStages{manifest: func(m *Manifest) {
			m.Identities = slices.DeleteFunc(m.Identities, func(id Identity) bool { return id.Pseudonym == bundleAcctA })
		}}, ErrManifest},
		"undeclared extra site": {bundleStages{manifest: func(m *Manifest) {
			m.Identities = append(m.Identities, syntheticIdentity("dom-00000c.example"))
			slices.SortFunc(m.Identities, func(a, b Identity) int { return strings.Compare(a.Pseudonym, b.Pseudonym) })
		}}, ErrManifest},
		"unordered":       {bundleStages{manifest: func(m *Manifest) { m.Identities[0], m.Identities[1] = m.Identities[1], m.Identities[0] }}, ErrManifest},
		"repeated":        {bundleStages{manifest: func(m *Manifest) { m.Identities = append(m.Identities, m.Identities[len(m.Identities)-1]) }}, ErrManifest},
		"digest prefix":   {bundleStages{manifest: func(m *Manifest) { m.Identities[0].Digest = strings.Repeat("9", 64) }}, ErrManifest},
		"short digest":    {bundleStages{manifest: func(m *Manifest) { m.Identities[0].Digest = m.Identities[0].Digest[:63] }}, ErrManifest},
		"not a pseudonym": {bundleStages{manifest: func(m *Manifest) { m.Identities[0].Pseudonym = "k-0000000000000001" }}, ErrManifest},
		"episode not declared": {bundleStages{rows: withEpisode, manifest: func(m *Manifest) {
			m.Identities = slices.DeleteFunc(m.Identities, func(id Identity) bool { return id.Pseudonym == episode })
		}}, ErrBundle},
		"declared episode unused": {bundleStages{manifest: func(m *Manifest) {
			m.Identities = append(m.Identities, syntheticIdentity(episode))
			slices.SortFunc(m.Identities, func(a, b Identity) int { return strings.Compare(a.Pseudonym, b.Pseudonym) })
		}}, ErrBundle},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validateFiles(buildBundle(t, tc.st), nil); !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
		})
	}
}
