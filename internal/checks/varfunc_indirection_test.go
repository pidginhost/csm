package checks

import "testing"

func TestDetectVarFuncDangerousAssignmentUppercaseEvalDecoder(t *testing.T) {
	content := "<?php\n" +
		"$decoder = 'Base64_Decode';\n" +
		"$runner = 'EVAL';\n" +
		"$runner($decoder('AAAA'));\n"
	if !detectVarFuncDangerousAssignment(content) {
		t.Fatal("uppercase PHP function names should still be detected")
	}
}

func TestDetectVarFuncDangerousAssignmentCommentGapBeforeCall(t *testing.T) {
	content := "<?php\n" +
		"$decoder = 'base64_decode';\n" +
		"$runner = 'eval';\n" +
		"$runner/* hidden */($decoder('AAAA'));\n"
	if !detectVarFuncDangerousAssignment(content) {
		t.Fatal("comment between variable function and paren should be treated as whitespace")
	}
}

func TestDetectVarFuncDangerousAssignmentGlobalQualifiedFunctionName(t *testing.T) {
	content := "<?php\n" +
		"$runner = '\\system';\n" +
		"$runner($_GET['cmd']);\n"
	if !detectVarFuncDangerousAssignment(content) {
		t.Fatal("global-qualified PHP function name should still be detected")
	}
}

func TestDetectVarFuncDangerousAssignmentAllowsDecoderCallbackAlone(t *testing.T) {
	content := "<?php\n" +
		"$decoder = 'base64_decode';\n" +
		"$value = $decoder($storedValue);\n"
	if detectVarFuncDangerousAssignment(content) {
		t.Fatal("decoder callback without an execution sink should not fire")
	}
}

func TestDetectVarFuncDangerousAssignmentShellRequiresRequestInput(t *testing.T) {
	content := "<?php\n" +
		"$runner = 'exec';\n" +
		"$thumb = $runner('convert ' . escapeshellarg($src));\n"
	if detectVarFuncDangerousAssignment(content) {
		t.Fatal("indirect shell helper without request input should not fire")
	}
}

func TestDetectVarFuncDangerousAssignmentShellWithRequestInput(t *testing.T) {
	content := "<?php\n" +
		"$runner = 'system';\n" +
		"$runner($_GET['cmd']);\n"
	if !detectVarFuncDangerousAssignment(content) {
		t.Fatal("indirect shell call with request input should fire")
	}
}

func TestDetectVarFuncDangerousAssignmentIgnoresQuotedSamples(t *testing.T) {
	content := "<?php\n" +
		"$example = '$runner = \"system\"; $runner($_GET[\"cmd\"]);';\n" +
		"echo $example;\n"
	if detectVarFuncDangerousAssignment(content) {
		t.Fatal("quoted sample code should not be parsed as executable PHP")
	}
}

func TestDetectVarFuncDangerousAssignmentRequiresAssignmentBeforeCall(t *testing.T) {
	content := "<?php\n" +
		"$runner($_GET['cmd']);\n" +
		"$runner = 'system';\n"
	if detectVarFuncDangerousAssignment(content) {
		t.Fatal("call before the dangerous assignment should not fire")
	}
}

func TestDetectVarFuncDangerousAssignmentSafeReassignmentClearsBinding(t *testing.T) {
	content := "<?php\n" +
		"$runner = 'system';\n" +
		"$runner = 'esc_html';\n" +
		"$runner($_GET['cmd']);\n"
	if detectVarFuncDangerousAssignment(content) {
		t.Fatal("safe reassignment before call should clear the dangerous binding")
	}
}
