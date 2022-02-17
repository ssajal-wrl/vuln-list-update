/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parse(t *testing.T) {
	type args struct {
		filePath string
	}
	testCases := []struct {
		name    string
		args    args
		want    *Vulnerability
		wantErr error
	}{
		{
			name: "perfect data",
			args: args{
				filePath: "./testdata/golden",
			},
			want: &Vulnerability{
                Candidate: "CVE-2020-24241",
                PublicDate: time.Date(2020, 8, 25, 0, 0, 0, 0, time.UTC),
                Description: "In Netwide Assembler (NASM) 2.15rc10, there is heap use-after-free in saa_wbytes in nasmlib/saa.c.",
				References: []string{},
				Notes: []string{},
				Priority: "medium",
                Bugs: []string{
					"LINCD-2974",
					"LIN1019-5289",
					"LIN1018-6614",
					"LIN10-7689",
                },
				Patches: map[Package]Statuses{
					Package("nasm"): {
						"10.17.41.1": {
							"Status": "released",
							"Note": "10.17.41.22"
						},
						"10.18.44.1": {
							"Status": "ignored",
							"Note": ""
						},
						10.19.45.1": {
							"Status": "pending",
							"Note": ""
						},
						"10.20.6.0": {
							"Status": "not-affected",
							"Note": ""
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.args.filePath)
			require.NoError(t, err)
			defer f.Close()

			got, gotErr := parse(f)
			assert.Equal(t, tc.wantErr, gotErr)
			assert.Equal(t, tc.want, got)
		})
	}
}
