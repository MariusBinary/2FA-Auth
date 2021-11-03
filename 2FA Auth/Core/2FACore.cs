using System;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Media.Imaging;
using QRCoder;

namespace _2FA_Auth.Core
{
	class _2FACore
	{
		static readonly DateTime Jan1st1970 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

		/// <summary>
		/// Return the current number to be checked. This can be compared against user input.
		/// </summary>
		public static String generateCurrentNumberString(String base32Secret, string algorithm, string digits, string period)
		{
			int number = generateNumber(base32Secret, algorithm, CurrentTimeMillis(), int.Parse(period));
			return zeroPrepend(number, int.Parse(digits));
		}

		/// <summary>
		/// Similar to {@link #generateNumberString(String, long, int)} but this returns a int instead of a string.
		/// </summary>
		public static int generateNumber(String base32Secret, string algorithm, long timeMillis, int timeStepSeconds)
		{
			byte[] key = decodeBase32(base32Secret);
			byte[] data = new byte[8];
			long value = timeMillis / 1000 / timeStepSeconds;
			for (int i = 7; value > 0; i--)
			{
				data[i] = (byte)(value & 0xFF);
				value >>= 8;
			}

			// encrypt the data with the key and return the SHA of it in hex.
			byte[] hash = new byte[] { };
			switch (algorithm.ToLower())
            {
				case "sha1":
					HMACSHA1 hmacsha1 = new HMACSHA1();
					hmacsha1.Key = key;
					hash = hmacsha1.ComputeHash(data);
					break;
				case "sha256":
					HMACSHA256 hmacsha256 = new HMACSHA256();
					hmacsha256.Key = key;
					hash = hmacsha256.ComputeHash(data);
					break;
				case "sha512":
					HMACSHA512 hmacsha512 = new HMACSHA512();
					hmacsha512.Key = key;
					hash = hmacsha512.ComputeHash(data);
					break;
			}

			// take the 4 least significant bits from the encrypted string as an offset
			int offset = hash[hash.Length - 1] & 0xF;

			// We're using a long because Java hasn't got unsigned int.
			long truncatedHash = 0;
			for (int i = offset; i < offset + 4; ++i)
			{
				truncatedHash <<= 8;
                // get the 4 bytes at the offset
                truncatedHash |= (hash[i] & 0xFF);
			}
			// cut off the top bit
			truncatedHash &= 0x7FFFFFFF;

			// the token is then the last 6 digits in the number
			truncatedHash %= 1000000;
			// this is only 6 digits so we can safely case it
			return (int)truncatedHash;
		}

		/// <summary>
		/// Ritorna il codice QR basato sui parametri forniti.
		/// </summary>
		public static BitmapImage generateQrCode(string label, string secret, string issuer, string algorithm, string digits, string period)
		{
			QRCodeGenerator qrGenerator = new QRCodeGenerator();
			QRCodeData qrCodeData = qrGenerator.CreateQrCode(generateUrl(label, secret, issuer, algorithm, digits, period), QRCodeGenerator.ECCLevel.M);
			QRCode qrCode = new QRCode(qrCodeData);
			Bitmap qrCodeImage = qrCode.GetGraphic(20, Color.FromArgb(224, 58, 63), Color.White, true);
			return Utils.ToBitmapImage(qrCodeImage);
		}

		/// <summary>
		/// Ritorna l'indirizzo URL basato sui parametri forniti.
		/// </summary>
		public static string generateUrl(string label, string secret, string issuer, string algorithm, string digits, string period)
		{
			return $"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}";
		}

		/// <summary>
		/// Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
		/// </summary>
		static String zeroPrepend(int num, int digits)
		{
			String numStr = num.ToString();
			if (numStr.Length >= digits)
			{
				return numStr;
			}
			else
			{
				StringBuilder sb = new StringBuilder(digits);
				int zeroCount = digits - numStr.Length;

                string blockOfZeros = "";
                for (int i = 0; i < digits; i++) {
                    blockOfZeros += '0';
                }

                sb.Append(blockOfZeros, 0, zeroCount);
				sb.Append(numStr);
				return sb.ToString();
			}
		}

		/// <summary>
		/// Decode base-32 method. I didn't want to add a dependency to Apache Codec just for this decode method. Exposed for testing.
		/// </summary>
		static byte[] decodeBase32(String str)
		{
			// each base-32 character encodes 5 bits
			int numBytes = ((str.Length * 5) + 7) / 8;
			byte[] result = new byte[numBytes];
			int resultIndex = 0;
			int which = 0;
			int working = 0;
			for (int i = 0; i < str.Length; i++)
			{
				char ch = str[i];
				int val = 0;
				if (ch >= 'a' && ch <= 'z')
				{
					val = ch - 'a';
				}
				else if (ch >= 'A' && ch <= 'Z')
				{
					val = ch - 'A';
				}
				else if (ch >= '2' && ch <= '7')
				{
					val = 26 + (ch - '2');
				}
				else if (ch == '=')
				{
					// special case
					which = 0;
					break;
				}
				else
				{
					//throw new IllegalArgumentException("Invalid base-32 character: " + ch);
				}
				/*
				 * There are probably better ways to do this but this seemed the most straightforward.
				 */
				switch (which)
				{
					case 0:
						// all 5 bits is top 5 bits
						working = (val & 0x1F) << 3;
						which = 1;
						break;
					case 1:
						// top 3 bits is lower 3 bits
						working |= (val & 0x1C) >> 2;
						result[resultIndex++] = (byte)working;
						// lower 2 bits is upper 2 bits
						working = (val & 0x03) << 6;
						which = 2;
						break;
					case 2:
						// all 5 bits is mid 5 bits
						working |= (val & 0x1F) << 1;
						which = 3;
						break;
					case 3:
						// top 1 bit is lowest 1 bit
						working |= (val & 0x10) >> 4;
						result[resultIndex++] = (byte)working;
						// lower 4 bits is top 4 bits
						working = (val & 0x0F) << 4;
						which = 4;
						break;
					case 4:
						// top 4 bits is lowest 4 bits
						working |= (val & 0x1E) >> 1;
						result[resultIndex++] = (byte)working;
						// lower 1 bit is top 1 bit
						working = (val & 0x01) << 7;
						which = 5;
						break;
					case 5:
						// all 5 bits is mid 5 bits
						working |= (val & 0x1F) << 2;
						which = 6;
						break;
					case 6:
						// top 2 bits is lowest 2 bits
						working |= (val & 0x18) >> 3;
						result[resultIndex++] = (byte)working;
						// lower 3 bits of byte 6 is top 3 bits
						working = (val & 0x07) << 5;
						which = 7;
						break;
					case 7:
						// all 5 bits is lower 5 bits
						working |= (val & 0x1F);
						result[resultIndex++] = (byte)working;
						which = 0;
						break;
				}
			}
			if (which != 0)
			{
				result[resultIndex++] = (byte)working;
			}
			if (resultIndex != result.Length)
			{
				result = Utils.CopyOf(result, resultIndex);
			}
			return result;
		}

		/// <summary>
		/// Ritorna il tempo corrente in millisecondi.
		/// </summary>
		public static long CurrentTimeMillis()
		{
			return (long)(DateTime.UtcNow - Jan1st1970).TotalMilliseconds;
		}
	}
}