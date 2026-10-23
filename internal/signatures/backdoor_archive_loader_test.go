package signatures

import "testing"

// A loader keeps its payload inside an archive, often password-protected, so
// the PHP on disk carries no code for a content scan to match. The bytes it
// runs are read out of the archive at request time.
func TestBackdoorArchiveLoader_DetectsArchiveCodeExecution(t *testing.T) {
	scanner := loadRepoScanner(t)

	samples := map[string]string{
		// Password-protected members joined and run in HTML mode, with the
		// sink in mixed case.
		"protected members joined into HTML-mode eval": `<?php $bundle = new ZipArchive;
if ($bundle->open("assets.dat") === TRUE) {
    $bundle->setPassword("example-pass");
    $parts = array();
    for ($n = 0; $n < $bundle->numFiles; $n++) {
        $parts[$bundle->getNameIndex($n)] = $bundle->getFromIndex($n);
    }
    ksort($parts, SORT_NATURAL);
    $body = implode("", $parts);
    EvAl("?>" . $body) ;
    $bundle->close();
}`,
		"member read inside eval": `<?php
$a = new ZipArchive();
$a->open(__DIR__ . '/cache.bin');
eval('?>' . $a->getFromName('main.php'));`,
		"member read inside assert": `<?php
$a = new ZipArchive();
$a->open('cache.bin');
assert($a->getFromName('init'));`,
		"member stream read into HTML-mode eval": `<?php
$a = new ZipArchive();
$a->open('cache.bin');
$h = $a->getStream('main.php');
$src = stream_get_contents($h);
eval('?>' . $src);`,
		"zip wrapper read inside eval":  `<?php eval('?>' . file_get_contents('zip://' . __DIR__ . '/cache.bin#main.php'));`,
		"phar wrapper read inside eval": `<?php eval(file_get_contents("phar://" . __DIR__ . "/cache.phar/run"));`,
		"protected member read run without HTML mode": `<?php
$a = new ZipArchive();
if ($a->open('cache.bin') === true) {
    $a->setPassword($key);
    $src = $a->getFromName('core.txt');
    eval($src);
}`,
	}
	for name, sample := range samples {
		t.Run(name, func(t *testing.T) {
			if !hasRule(scanner.ScanContent([]byte(sample), ".php"), "backdoor_archive_loader") {
				t.Errorf("backdoor_archive_loader miss: %s", name)
			}
		})
	}
}

// Extracting an archive to disk, reading data members, and evaluating local
// template text are everyday code. None of them runs archive bytes as PHP.
func TestBackdoorArchiveLoader_IgnoresOrdinaryArchiveAndTemplateCode(t *testing.T) {
	scanner := loadRepoScanner(t)

	samples := map[string]string{
		// The core unzip helper shape: every member is read and written to
		// disk, never evaluated.
		"extraction to disk": `<?php
function example_unzip($file, $to) {
    $z = new ZipArchive();
    if (true !== $z->open($file, ZipArchive::CHECKCONS)) {
        return false;
    }
    for ($i = 0; $i < $z->numFiles; $i++) {
        $info = $z->statIndex($i);
        $contents = $z->getFromIndex($i);
        if (false === $contents) {
            return false;
        }
        file_put_contents($to . $info['name'], $contents);
    }
    $z->close();
    return true;
}`,
		// A spreadsheet reader parses XML members.
		"data member parsed as XML": `<?php
$z = new ZipArchive();
$z->open($path);
$xml = simplexml_load_string($z->getFromName('xl/workbook.xml'));`,
		// A backup tool encrypts what it writes and checks a manifest.
		"encrypted backup writer": `<?php
$z = new ZipArchive();
$z->open($target, ZipArchive::CREATE);
$z->setPassword($secret);
$z->addFile($dump, 'db.sql');
$z->setEncryptionName('db.sql', ZipArchive::EM_AES_256);
$manifest = json_decode($z->getFromName('manifest.json'), true);
assert(is_array($manifest));
$z->close();`,
		// A template engine evaluates the template it just compiled; a token
		// stream accessor shares the method name with the archive API but
		// takes no member name.
		"template engine with a token stream": `<?php
final class Environment {
    public function load($name) {
        $stream = $this->parser->getStream();
        $content = $this->compileSource($stream);
        eval('?>' . $content);
    }
}`,
		"local template file evaluated": `<?php
$template = file_get_contents(__DIR__ . '/views/page.tpl');
eval('?>' . $template);`,
	}
	for name, sample := range samples {
		t.Run(name, func(t *testing.T) {
			if m := scanner.ScanContent([]byte(sample), ".php"); hasRule(m, "backdoor_archive_loader") {
				t.Errorf("backdoor_archive_loader FP on %s", name)
			}
		})
	}
}

// Including a path through the zip:// wrapper runs a member straight out of
// the archive. The include forms without parentheses and the _once variants
// do the same thing as the parenthesised form.
func TestStreamWrapperIncludeOfZipMemberEveryForm(t *testing.T) {
	scanner := loadRepoScanner(t)

	samples := map[string]string{
		"include without parentheses":      `<?php include 'zip://' . __DIR__ . '/cache.bin#main.php';`,
		"require_once with parentheses":    `<?php require_once("zip://cache.bin#main.php");`,
		"include_once without parentheses": `<?php include_once "zip://cache.bin#main.php";`,
	}
	for name, sample := range samples {
		t.Run(name, func(t *testing.T) {
			if !hasRule(scanner.ScanContent([]byte(sample), ".php"), "dropper_php_stream_wrapper") {
				t.Errorf("dropper_php_stream_wrapper miss: %s", name)
			}
		})
	}
}
