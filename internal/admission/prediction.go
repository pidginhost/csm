package admission

import "fmt"

// Prediction is what a dry-run forecast says live admission would have done
// with a pick. It is not a terminal reason: every forecast pick
// ends as a dry run, and the prediction only counts.
type Prediction uint8

const (
	// PredictCapacityAdmit: the pick passes the modelled ceiling and
	// temporary-capacity checks. It is not proof a block would apply.
	PredictCapacityAdmit Prediction = iota + 1
	// PredictExistingActual: a real proven block already covers it.
	PredictExistingActual
	// PredictExistingShadow: this session already forecast a covering block.
	PredictExistingShadow
	// PredictCeiling: it would wait for modelled usage or paced credit.
	PredictCeiling
	// PredictSetFull: it would wait for real-plus-forecast temporary room.
	PredictSetFull
	// PredictPendingRecovery: a shorter forecast block holds the address.
	PredictPendingRecovery
	// PredictForecastLimited: the forecast models no more active blocks.
	PredictForecastLimited
	// PredictNotModelled: the kind has no capacity model.
	PredictNotModelled
	// PredictCapacityEvict: the pick passes the modelled ceiling and takes
	// the temporary slot of a strictly lower-tier automatic block, which it
	// would replace.
	PredictCapacityEvict
	// PredictCapacityRotate: the pick passes the modelled ceiling and
	// rotates an equal-tier forecast block whose hold passed out of its
	// full partition, as fresh work may.
	PredictCapacityRotate
	// PredictEqualTierWait: it would wait as set_full while its partition
	// holds an equal-tier block that rotation does not give it yet: the
	// block's hold, the shares or an answered episode stop it.
	PredictEqualTierWait
	predictionEnd
)

// PredictionSlots sizes an array indexed by Prediction; slot zero is unused.
const PredictionSlots = int(predictionEnd)

var predictionNames = [...]string{"", "capacity_admit", "existing_actual", "existing_shadow", "ceiling", "set_full", "pending_recovery", "forecast_limited", "not_modelled", "capacity_evict", "capacity_rotate", "equal_tier_wait"}

func (p Prediction) Valid() bool { return p >= PredictCapacityAdmit && p < predictionEnd }

func (p Prediction) String() string {
	if p.Valid() {
		return predictionNames[p]
	}
	return fmt.Sprintf("prediction(%d)", uint8(p))
}
