package signatures

// RegexPair contributes one regex match when the start offsets of its two
// expressions are within MaxDistance bytes, in either order.
type RegexPair struct {
	First       string `yaml:"first"`
	Second      string `yaml:"second"`
	MaxDistance int    `yaml:"max_distance"`
}

type compiledRegexPair struct {
	first, second *compiledRegex
	maxDistance   int
}

func (e *regexEval) matchPair(pair compiledRegexPair) bool {
	if !e.match(pair.first) || !e.match(pair.second) {
		return false
	}
	first := pair.first.FindAllIndex(e.content, -1)
	second := pair.second.FindAllIndex(e.content, -1)
	// Both lists are sorted. Advancing the earlier match examines each offset
	// once instead of testing every pair or running a wide-gap regex.
	for i, j := 0, 0; i < len(first) && j < len(second); {
		distance := first[i][0] - second[j][0]
		if distance >= -pair.maxDistance && distance <= pair.maxDistance {
			return true
		}
		if distance < 0 {
			i++
		} else {
			j++
		}
	}
	return false
}
