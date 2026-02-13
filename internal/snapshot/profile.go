// Profile definitions for Dart AOT snapshot format variations.
package snapshot

// ProfileID identifies a specific Dart AOT snapshot format profile.
type ProfileID string

const (
	ProfileAndroidARM64CompressedPtrs ProfileID = "android-arm64-compressedptrs"
	ProfileAndroidARM64NoCompress     ProfileID = "android-arm64-nocompress"
	ProfileUnknown                    ProfileID = "unknown"
)

// Profile holds per-version constants for snapshot layout parsing.
type Profile struct {
	ID                 ProfileID `json:"id"`
	CompressedPointers bool      `json:"compressed_pointers"`
	NullSafety         bool      `json:"null_safety"`
	TaggedPointerShift int       `json:"tagged_pointer_shift"` // typically 1
	ObjectAlignment    int       `json:"object_alignment"`     // typically 8 or 16
}

// DetectProfile guesses a profile from snapshot header features.
func DetectProfile(hdr *Header) Profile {
	if hdr == nil {
		return Profile{ID: ProfileUnknown}
	}

	p := Profile{
		ID:                 ProfileUnknown,
		TaggedPointerShift: 1,
		ObjectAlignment:    8,
	}

	features := hdr.FeatureList()
	for _, f := range features {
		switch f {
		case "compressed-pointers":
			p.CompressedPointers = true
		case "null-safety":
			p.NullSafety = true
		case "no-null-safety":
			p.NullSafety = false
		}
	}

	// Check for arm64 android
	hasARM64 := false
	hasAndroid := false
	for _, f := range features {
		switch f {
		case "arm64", "arm64-sysv":
			hasARM64 = true
		case "android":
			hasAndroid = true
		}
	}

	if hasARM64 || hasAndroid {
		if p.CompressedPointers {
			p.ID = ProfileAndroidARM64CompressedPtrs
		} else {
			p.ID = ProfileAndroidARM64NoCompress
		}
	}

	return p
}
