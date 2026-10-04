package signatures

import "testing"

// Library and cache code that the default ignore list used to hide from the
// realtime engine. Each rule below fired on stock third-party code once those
// paths were scanned; the samples are reduced from the published libraries.

func TestFPVendor_YML_IonCubeFake_ComposerDiagnose(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php
namespace Composer\Command;

class DiagnoseCommand extends BaseCommand
{
    private function checkPlatform()
    {
        $warnings = array();
        if (extension_loaded('ionCube Loader') && ioncube_loader_iversion() < 40009) {
            $warnings['ioncube'] = ioncube_loader_version();
        }
        foreach ($warnings as $warning => $current) {
            switch ($warning) {
                case 'ioncube':
                    $text = "Your ionCube Loader extension (".$current.") is incompatible with Phar files.";
                    break;
            }
        }
        return $warnings;
    }
}
`)
	if hasRule(s.ScanContent(legit, ".php"), "obfuscation_ionCube_fake") {
		t.Error("obfuscation_ionCube_fake FP: matched an ionCube extension check with no decoder")
	}
}

func TestFPVendor_YML_IonCubeFake_MarkerBeforeLoader(t *testing.T) {
	s := loadRepoScanner(t)
	loader := []byte(`<?php
/* This file is protected by ionCube Encoder */
eval(gzinflate(base64_decode('S03OyFdIzs8rSc0rUVTyyM/LU0hKLM4pzs9RBAA=')));
`)
	if !hasRule(s.ScanContent(loader, ".php"), "obfuscation_ionCube_fake") {
		t.Error("obfuscation_ionCube_fake missed a fake ionCube loader that names the encoder before its decoder")
	}
}

func TestFPVendor_YML_IonCubeFake_DecoderFarFromMarker(t *testing.T) {
	s := loadRepoScanner(t)
	padding := make([]byte, 900)
	for i := range padding {
		padding[i] = ' '
	}
	far := []byte("<?php\n// requires the ionCube Loader extension\n" + string(padding) +
		"\n$data = eval(base64_decode($blob));\n")
	if hasRule(s.ScanContent(far, ".php"), "obfuscation_ionCube_fake") {
		t.Error("obfuscation_ionCube_fake FP: matched a decoder outside the proximity window")
	}
}
