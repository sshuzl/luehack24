import java.util.Base64;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Solve {
	static String ctx_correct = "GgyJZHeh911GCsm0fpQjE3rxjwk5dZyDl7vxHHJku7CwPMoR3Ykcuty2WzmrgEny";

	private static byte[] getKeyBytes() {
		byte[] arrayOfByte1 = new byte[16];
		byte[] tmp8_6 = arrayOfByte1;
		tmp8_6[0] = -85;
		byte[] tmp13_8 = tmp8_6;
		tmp13_8[1] = -83;
		byte[] tmp18_13 = tmp13_8;
		tmp18_13[2] = -79;
		byte[] tmp23_18 = tmp18_13;
		tmp23_18[3] = -70;
		byte[] tmp28_23 = tmp23_18;
		tmp28_23[4] = -66;
		byte[] tmp33_28 = tmp28_23;
		tmp33_28[5] = -64;
		byte[] tmp38_33 = tmp33_28;
		tmp38_33[6] = -36;
		byte[] tmp44_38 = tmp38_33;
		tmp44_38[7] = -34;
		byte[] tmp50_44 = tmp44_38;
		tmp50_44[8] = -22;
		byte[] tmp56_50 = tmp50_44;
		tmp56_50[9] = -19;
		byte[] tmp62_56 = tmp56_50;
		tmp62_56[10] = -2;
		byte[] tmp68_62 = tmp62_56;
		tmp68_62[11] = 13;
		byte[] tmp74_68 = tmp68_62;
		tmp74_68[12] = 21;
		byte[] tmp80_74 = tmp74_68;
		tmp80_74[13] = 29;
		byte[] tmp86_80 = tmp80_74;
		tmp86_80[14] = 90;
		byte[] tmp92_86 = tmp86_80;
		tmp92_86[15] = 112;
		// tmp92_86;
		byte[] arrayOfByte2 = new byte[16];
		int j = 0;
		while (j < arrayOfByte2.length) {
			int i;
			int k;
			switch (j) {
				case 6:
				default:
					i = arrayOfByte1[j];
					break;
				case 8:
				case 11:
				case 14:
					if (j < 13) {
						k = 1;
					} else {
						k = -1;
					}
					i = arrayOfByte1[(k + j)];
					break;
				case 7:
				case 9:
					if (j < 8) {
						k = 4;
					} else {
						k = -4;
					}
					i = arrayOfByte1[(k + j)];
					break;
				case 4:
				case 5:
					i = arrayOfByte1[(j - 2)];
					break;
				case 3:
				case 15:
					k = 7;
					if (j >= 7) {
						k = -7;
					}
					i = arrayOfByte1[(k + j)];
					break;
				case 2:
				case 12:
				case 13:
					k = 12;
					if (j >= 12) {
						k = -12;
					}
					i = arrayOfByte1[(k + j)];
					break;
				case 1:
				case 10:
					if (j < 6) {
						k = 3;
					} else {
						k = -3;
					}
					i = arrayOfByte1[(k + j)];
					break;
				case 0:
					i = arrayOfByte1[(j + 15)];
			}
			arrayOfByte2[j] = (byte) i;
			j += 1;
		}
		return arrayOfByte2;
	}

	private static byte[] initIV(int paramInt) {
		byte[] arrayOfByte = new byte[paramInt];
		arrayOfByte[0] = 69;
		paramInt = 1;
		while (paramInt < arrayOfByte.length) {
			arrayOfByte[paramInt] = ((byte) (arrayOfByte[(paramInt - 1)] ^ paramInt));
			paramInt += 1;
		}
		return arrayOfByte;
	}

	public static String getPw() {
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			IvParameterSpec iv = new IvParameterSpec(initIV(c.getBlockSize()));
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(getKeyBytes(), "AES"), iv);
			byte[] ct = Base64.getDecoder().decode(ctx_correct);
			byte[] flag = c.doFinal(ct);
			return new String(flag);
		} catch (BadPaddingException paramString) {
			paramString.printStackTrace();
		} catch (IllegalBlockSizeException paramString) {
			paramString.printStackTrace();
		} catch (InvalidAlgorithmParameterException paramString) {
			paramString.printStackTrace();
		} catch (InvalidKeyException paramString) {
			paramString.printStackTrace();
		} catch (NoSuchPaddingException paramString) {
			paramString.printStackTrace();
		} catch (NoSuchAlgorithmException paramString) {
			paramString.printStackTrace();
		}
		return "ERROR";
	}

	public static void main(String[] args) {
		System.out.println(getPw());
	}
}
