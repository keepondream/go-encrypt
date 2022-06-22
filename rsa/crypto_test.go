package rsa

import (
	"bytes"
	"fmt"
	"testing"
)

const PUBK = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq0eBPEdySMFhUo+Y7fS3
u8s9qHiKTzEX2+KRoTXRKSPw1h9sGmfArrQlyqTusIa0LF/+3Vx9356h+hATZqbG
DnS34qIsNjdbElN2whq52HuhcZbw+klk96SX8F8r0eGwhSiqqT7YVc+3efuCVjj2
5da/D8xQZg91lwUS8G0merpYYLz6vxlVnJtcNJUK7M1eyCksdZQ5yz9YPK926aAu
pt4SEkBN7n/vmTUsep8clYwjxtumRMaAcj+xfSXH8VkDLMDHFbYAOlZmSiXbQHYi
bxglW/w2g3sHSytEguAGymBfp5onKj/oy0BJI0aCfd/PMKeF9rvCMnPiF06Usv96
7wIDAQAB
-----END PUBLIC KEY-----
`

const PRIK = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCrR4E8R3JIwWFS
j5jt9Le7yz2oeIpPMRfb4pGhNdEpI/DWH2waZ8CutCXKpO6whrQsX/7dXH3fnqH6
EBNmpsYOdLfioiw2N1sSU3bCGrnYe6FxlvD6SWT3pJfwXyvR4bCFKKqpPthVz7d5
+4JWOPbl1r8PzFBmD3WXBRLwbSZ6ulhgvPq/GVWcm1w0lQrszV7IKSx1lDnLP1g8
r3bpoC6m3hISQE3uf++ZNSx6nxyVjCPG26ZExoByP7F9JcfxWQMswMcVtgA6VmZK
JdtAdiJvGCVb/DaDewdLK0SC4AbKYF+nmicqP+jLQEkjRoJ9388wp4X2u8Iyc+IX
TpSy/3rvAgMBAAECggEAIRbWU8Plw0KAv8d4Hvh5CnGwPrzS04vDdTpnMgLInq8P
1v4JD2zd36Jz7ptAdaAAbNY60Z8NvkbSOhIi/WDYwHAyGjmEWxEEqhyvw74QC0+P
F/e2JFRLikAlDk4ElC6KwJ7joYC/oIxZgNpjCq9Em5CKJs4s9hqkeAGF8CbWGT1X
7n8akkT38SmtqifQTiwENa7FCcqzDQtLI2D3eM3wXWJW4ajVyAhV2QnGP2btK/oJ
MIDkr56Q1c/Zu5/qDnm8OP/kf34LqfSApWXGKtL8C97LVWCef+Q0xaubJx5qGoJY
9rhmbJaM8M4HYCA0YKKPDSYIOHb6Q5sJxAqqo0Pm0QKBgQDTFS5MNZR5taS8P2Yn
vnoKbyFEtLVfJG2J5d9GlCeE8OAb7eY6bfesg7+WJYHoEvL+wfAB75t9C+oIz7BG
sJ//CgtSledh6i3mIZ6hLGA9GKlas7cXlcLFJHzfyJnSBJ03nby8ATMaxS9VZ53a
tgQCwdgQhKdA0Hp1I3xuO/s6mQKBgQDPugQiyswMPppJGQsCMrTmw4ccvM/LMFib
MLJ9QPXb7gbFmEbB8GJ0MIp9DfALD95Acj77sOtaVhWczJBXu/Hrjc8+xJ+f/cfC
DlCu6k8PJ5ZWRR065vPATbKFlwpPr7GTdrhAiajedHxlLpM7kZxbG6pzEeQ/LAro
c7Nxde8exwKBgAhUO6FyM8uhqUBsWAGVeIdU30EwyD9a1p+sXGUSj4SlZJJ1jrIb
iLxb7oFkNX4M0V3QFUJeTAphH/j9CP2hFo8fvFaj559reCguh23grGN8x6H2mXDq
zeati+fgqIErAXEiXkIk4flacoWyMv5gVEQvlfEA6wCZuVtJ7S0EXONxAoGAZZk/
qJyzzFFaOOJsxfhzDmMX1HBs2Z6d19mrkyOQnK8A1Ogzw2uFW/rZ4WxNubtbIv49
2/CeTCLKk1RiTOb53hIQCU02HZSMfVdvEv47CNh96VgIgeSv16Co7jn/qxXtrohk
efxageNLbFmpXXtMlCsl5P4dOuCZvTPJ0nayK8UCgYB50ycXkoHgxXuyT8z85Q6/
RBEcZ5oX9EHCXhW957eH7Fz+cHs6qlYN3WOnT+93+BQNI3YdUFU+HEL0F3TWqHNx
fpahlDTRnfhvU99Ak3O4m9ezxzddSZzrivm1FNNgx2u0HpMqzihklP4pDyalg4r7
LKZxIJLMOwuXEqCHJlxuoA==
-----END PRIVATE KEY-----
`

func TestRSA_Encrypt(t *testing.T) {
	type args struct {
		plainText []byte
		pubKeyBuf []byte
	}
	tests := []struct {
		name           string
		r              *RSA
		args           args
		wantCipherText []byte
		wantErr        bool
	}{
		{
			name: "测试加密",
			r:    &RSA{},
			args: args{
				plainText: []byte("hello rsa 非对称加密 , good"),
				pubKeyBuf: []byte(PUBK),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCipherText, err := tt.r.Encrypt(tt.args.plainText, tt.args.pubKeyBuf)

			if err != nil {
				t.Errorf("RSA.Encrypt() error = %v", err)
				return
			}

			// 解密验证
			plainText, err := tt.r.Decrypt(gotCipherText, []byte(PRIK))
			if err != nil {
				t.Errorf("RSA.Decrypt() error = %v", err)
				return
			}

			fmt.Println("decrypt ------ val is : ")
			fmt.Println(string(plainText))

			fmt.Println("------- plain text is: ")
			fmt.Println(string(tt.args.plainText))

			if !bytes.Equal(plainText, tt.args.plainText) {
				t.Fatalf("decrypt val not equal plain texgt")
			}

		})
	}
}
