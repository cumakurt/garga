package checker

import "testing"

func TestWatermarkRequiredFreeSupportsRatiosBytesAndHeadroom(t *testing.T) {
	t.Parallel()

	const tebibyte = int64(1 << 40)
	tests := []struct {
		name      string
		total     int64
		watermark string
		headroom  string
		want      int64
	}{
		{name: "percentage", total: tebibyte, watermark: "90%", want: tebibyte / 10},
		{name: "ratio", total: tebibyte, watermark: "0.90", want: tebibyte / 10},
		{name: "absolute", total: tebibyte, watermark: "50gb", want: 50 << 30},
		{name: "headroom cap", total: 100 * tebibyte, watermark: "90%", headroom: "150gb", want: 150 << 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := watermarkRequiredFree(test.total, test.watermark, test.headroom)
			if !ok || got != test.want {
				t.Fatalf("watermarkRequiredFree() = %d, %t; want %d, true", got, ok, test.want)
			}
		})
	}
}

func TestWatermarkExceededUsesFreeSpaceSemantics(t *testing.T) {
	t.Parallel()

	if !watermarkExceeded(1000, 99, "90%", "") {
		t.Fatal("99 free bytes should exceed a 90% used watermark on a 1000-byte disk")
	}
	if watermarkExceeded(1000, 101, "90%", "") {
		t.Fatal("101 free bytes should remain below a 90% used watermark")
	}
}
