using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Program
{
    // ---- PIV sabitleri ----
    static readonly byte[] PivAid = new byte[] { 0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00 };
    const byte Slot9C = 0x9C;
    static readonly byte[] OidCert9C = new byte[] { 0x5F, 0xC1, 0x0B };

    static void Main()
    {
        try
        {
            Console.Write("PIN (varsayılan 123456 olabilir): ");
            string? pinStr = ReadHidden();
            if (string.IsNullOrEmpty(pinStr)) throw new Exception("PIN boş.");

            string message = "imzalanacak metin";

            using var sc = SmartCard.ConnectFirstPresent();
            Console.WriteLine("[*] Reader: " + sc.ReaderName);

            // SELECT PIV AID
            ApduOk(sc.Transmit(new Apdu(0x00, 0xA4, 0x04, 0x00, PivAid)));

            // 9C sertifikayı getir ve PEM yazdır
            byte[] certDer = GetCert9C(sc);
            var cert = new X509Certificate2(certDer);
            Console.WriteLine("[*] 9C Subject: " + cert.Subject);
            Console.WriteLine("[*] 9C PublicKey: " + cert.GetKeyAlgorithm());

            string pem = ToPem("CERTIFICATE", certDer);
            Console.WriteLine("\n----- 9C CERT PEM -----\n" + pem);

            // PIN VERIFY (global, P2=0x80)
            ApduOk(sc.Transmit(new Apdu(0x00, 0x20, 0x00, 0x80, Encoding.ASCII.GetBytes(pinStr))));

            // Mesajı imzala (alg sertifikadan tespit edilir)
            byte[] sig = Sign9C(sc, cert, Encoding.UTF8.GetBytes(message));
            string sigB64 = Convert.ToBase64String(sig);
            Console.WriteLine("\n[*] Signature (Base64):\n" + sigB64);

            // Yerelde doğrula (demo)
            bool ok = VerifyLocal(cert, message, sig);
            Console.WriteLine("\n[VERIFY-LOCAL] " + (ok ? "OK" : "FAIL"));
        }
        catch (Exception ex)
        {
            Console.WriteLine("HATA: " + ex);
        }
    }

    // ---- 9C sertifika GET DATA ----
    static byte[] GetCert9C(SmartCard sc)
    {
        // SELECT (zaten seçiliyse tekrar zararı yok)
        ApduOk(sc.Transmit(new Apdu(0x00, 0xA4, 0x04, 0x00, PivAid)));

        // GET DATA: 00 CB 3F FF [ 5C 03 5F C1 0B ]
        byte[] data = Tlv(0x5C, OidCert9C);
        var resp = sc.Transmit(new Apdu(0x00, 0xCB, 0x3F, 0xFF, data));
        ApduOk(resp);

        // çoğunlukla 53 [ 70 [ DER ] ]
        byte[] der = TryExtractCertDer(resp.Data) 
                     ?? throw new Exception("9C sertifika DER bulunamadı.");
        return der;
    }

    // ---- Imzalama (GENERAL AUTHENTICATE) ----
    static byte[] Sign9C(SmartCard sc, X509Certificate2 cert, byte[] message)
    {
        string alg = cert.GetKeyAlgorithm();
        byte[] toBeSigned;
        string note;

        if (alg.Contains("RSA", StringComparison.OrdinalIgnoreCase))
        {
            byte[] hash = SHA256.HashData(message);
            toBeSigned = BuildDigestInfoSha256(hash); // PKCS#1 DigestInfo
            note = "RSA/PKCS1v1.5 + SHA-256";
        }
        else if (alg.Contains("ECDSA", StringComparison.OrdinalIgnoreCase) || alg.Contains("EC", StringComparison.OrdinalIgnoreCase))
        {
            int bits = 256;
            try
            {
                var ecpub = cert.GetECDsaPublicKey();
                if (ecpub != null)
                {
                    // Curve üzerinden bit tahmini (basit yaklaşım)
                    string curve = ecpub.ExportParameters(false).Curve.Oid.FriendlyName ?? "";
                    bits = curve.Contains("384") ? 384 : 256;
                }
            } catch { }
            if (bits >= 384)
            {
                byte[] hash = SHA384.HashData(message);
                toBeSigned = hash; // ECDSA için GA ham hash bekler
                note = "ECDSA + SHA-384";
            }
            else
            {
                byte[] hash = SHA256.HashData(message);
                toBeSigned = hash;
                note = "ECDSA + SHA-256";
            }
        }
        else
        {
            throw new Exception("Desteklenmeyen public key: " + alg);
        }

        // GA verisi: 7C [ 82 [ toBeSigned ] ]
        byte[] ga = Tlv(0x7C, Tlv(0x82, toBeSigned));
        var resp = sc.Transmit(new Apdu(0x00, 0x87, 0x00, Slot9C, ga));
        ApduOk(resp);

        byte[] sig = ExtractNestedTlv(resp.Data, 0x7C, 0x82) 
                     ?? throw new Exception("İmza TLV yok.");
        Console.WriteLine("[*] GA OK (" + note + "), sigLen=" + sig.Length);
        return sig;
    }

    // ---- Yerelde doğrulama (demo) ----
    static bool VerifyLocal(X509Certificate2 cert, string message, byte[] sig)
    {
        if (cert.GetKeyAlgorithm().Contains("RSA", StringComparison.OrdinalIgnoreCase))
        {
            using var rsa = cert.GetRSAPublicKey()!;
            return rsa.VerifyData(Encoding.UTF8.GetBytes(message), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            using var ecdsa = cert.GetECDsaPublicKey()!;
            // GA dönüşü ECDSA DER (r,s) biçimindedir → VerifyData bunu bekler
            // Hash, curve ebatına göre seçildi (256/384)
            int bits = 256;
            try
            {
                var ecp = ecdsa.ExportParameters(false);
                string name = ecp.Curve.Oid.FriendlyName ?? "";
                bits = name.Contains("384") ? 384 : 256;
            } catch { }
            var hashAlg = (bits >= 384) ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
            return ecdsa.VerifyData(Encoding.UTF8.GetBytes(message), sig, hashAlg);
        }
    }

    // ---- TLV ve ASN.1 yardımcıları ----
    static byte[] Tlv(int tag, byte[] value)
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)tag);
        WriteLen(ms, value.Length);
        ms.Write(value, 0, value.Length);
        return ms.ToArray();
    }
    static void WriteLen(Stream s, int len)
    {
        if (len < 0x80)
        {
            s.WriteByte((byte)len);
        }
        else if (len <= 0xFF)
        {
            s.WriteByte(0x81); s.WriteByte((byte)len);
        }
        else
        {
            s.WriteByte(0x82);
            s.WriteByte((byte)((len >> 8) & 0xFF));
            s.WriteByte((byte)(len & 0xFF));
        }
    }

    static (int tag, byte[] val)? ReadTlv(ReadOnlySpan<byte> buf, ref int pos)
    {
        if (pos >= buf.Length) return null;
        int tag = buf[pos++] & 0xFF;
        if (pos >= buf.Length) return null;
        int len = buf[pos++] & 0xFF;
        if (len == 0x81) { if (pos >= buf.Length) return null; len = buf[pos++] & 0xFF; }
        else if (len == 0x82) { if (pos + 1 >= buf.Length) return null; len = (buf[pos++] << 8) | buf[pos++]; }
        else if (len >= 0x80) throw new Exception("Desteklenmeyen length formu");
        if (pos + len > buf.Length) return null;
        var val = buf.Slice(pos, len).ToArray();
        pos += len;
        return (tag, val);
    }

    static byte[] ExtractNestedTlv(byte[] data, int outerTag, int innerTag)
    {
        int p = 0;
        var outer = ReadTlv(data, ref p);
        if (outer == null || outer.Value.tag != outerTag) return null;
        int q = 0;
        var span = outer.Value.val.AsSpan();
        while (q < span.Length)
        {
            var inner = ReadTlv(span, ref q);
            if (inner == null) break;
            if (inner.Value.tag == innerTag) return inner.Value.val;
        }
        return null;
    }

    static byte[] TryExtractCertDer(byte[] resp)
    {
        int p = 0;
        var t = ReadTlv(resp, ref p);
        if (t == null) return null;
        if (t.Value.tag == 0x70) return t.Value.val; // direkt DER
        int q = 0;
        var t2 = ReadTlv(t.Value.val, ref q);
        if (t2 != null && t2.Value.tag == 0x70) return t2.Value.val;
        return null;
    }

    // ASN.1 DigestInfo for SHA-256: SEQ { algId(sha256), NULL } + OCTET STRING(hash)
    static byte[] BuildDigestInfoSha256(byte[] sha256)
    {
        // 30 31
        //   30 0d
        //     06 09 60 86 48 01 65 03 04 02 01  (2.16.840.1.101.3.4.2.1)
        //     05 00
        //   04 20 [hash32]
        var prefix = new byte[] {
            0x30,0x31, 0x30,0x0d,
            0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,
            0x05,0x00, 0x04,0x20
        };
        var result = new byte[prefix.Length + sha256.Length];
        Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
        Buffer.BlockCopy(sha256, 0, result, prefix.Length, sha256.Length);
        return result;
    }

    static string ToPem(string kind, byte[] der)
    {
        string b64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN {kind}-----\n{b64}\n-----END {kind}-----\n";
    }

    static void ApduOk(ApduResponse r)
    {
        if (r.SW != 0x9000)
            throw new Exception($"APDU hata: {r.SW:X4}");
    }

    static string? ReadHidden()
    {
        var sb = new StringBuilder();
        for (;;)
        {
            var key = Console.ReadKey(intercept:true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0) { sb.Remove(sb.Length-1,1); continue; }
            if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
        }
        return sb.ToString();
    }
}

#region SmartCard PC/SC (winscard) + APDU
sealed class SmartCard : IDisposable
{
    IntPtr _ctx;
    IntPtr _card;
    string _reader = "";

    public string ReaderName => _reader;

    private SmartCard() {}

    public static SmartCard ConnectFirstPresent()
    {
        var sc = new SmartCard();
        int rc;

        rc = WinSCard.SCardEstablishContext(WinSCard.SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out sc._ctx);
        Check(rc, "SCardEstablishContext");

        // List readers
        uint sz = 0;
        rc = WinSCard.SCardListReaders(sc._ctx, null, null, ref sz);
        Check(rc, "SCardListReaders(size)");
        var buf = new byte[sz];
        rc = WinSCard.SCardListReaders(sc._ctx, null, buf, ref sz);
        Check(rc, "SCardListReaders");

        var readers = MultiStringToList(buf);
        if (readers.Count == 0) throw new Exception("Reader bulunamadı.");

        // İlk takılı karta bağlanmayı dene
        foreach (var r in readers)
        {
            IntPtr card;
            uint proto;
            rc = WinSCard.SCardConnect(sc._ctx, r, WinSCard.SCARD_SHARE_SHARED,
                                       WinSCard.SCARD_PROTOCOL_T0 | WinSCard.SCARD_PROTOCOL_T1,
                                       out card, out proto);
            if (rc == WinSCard.SCARD_S_SUCCESS)
            {
                sc._card = card;
                sc._reader = r;
                return sc;
            }
        }
        throw new Exception("Kart takılı reader bulunamadı.");
    }

    public ApduResponse Transmit(Apdu apdu)
    {
        // Yapılandır
        var send = apdu.ToArray();
        var recv = new byte[4096];
        var ioSend = new WinSCard.SCARD_IO_REQUEST { dwProtocol = WinSCard.SCARD_PROTOCOL_T1, cbPciLength = (uint)Marshal.SizeOf<WinSCard.SCARD_IO_REQUEST>() };
        var ioRecv = new WinSCard.SCARD_IO_REQUEST { dwProtocol = WinSCard.SCARD_PROTOCOL_T1, cbPciLength = (uint)Marshal.SizeOf<WinSCard.SCARD_IO_REQUEST>() };
        int r = WinSCard.SCardTransmit(_card, ref ioSend, send, send.Length, ref ioRecv, recv, out uint recvLen);
        Check(r, "SCardTransmit");

        if (recvLen < 2) throw new Exception("APDU dönüşü geçersiz.");
        ushort sw = (ushort)(recv[recvLen - 2] << 8 | recv[recvLen - 1]);
        var data = new byte[recvLen - 2];
        Array.Copy(recv, 0, data, 0, data.Length);
        return new ApduResponse(data, sw);
    }

    public void Dispose()
    {
        if (_card != IntPtr.Zero) { WinSCard.SCardDisconnect(_card, WinSCard.SCARD_LEAVE_CARD); _card = IntPtr.Zero; }
        if (_ctx  != IntPtr.Zero) { WinSCard.SCardReleaseContext(_ctx); _ctx = IntPtr.Zero; }
    }

    static void Check(int rc, string where)
    {
        if (rc != WinSCard.SCARD_S_SUCCESS)
            throw new Win32Exception(rc, $"{where} failed: 0x{rc:X}");
    }

    static System.Collections.Generic.List<string> MultiStringToList(byte[] multiSz)
    {
        var list = new System.Collections.Generic.List<string>();
        int i = 0;
        while (i < multiSz.Length)
        {
            int start = i;
            while (i < multiSz.Length && multiSz[i] != 0) i++;
            int len = i - start;
            if (len == 0) break;
            string s = Encoding.Unicode.GetString(multiSz, start, len);
            list.Add(s);
            i++; // skip null
        }
        return list;
    }
}

readonly struct Apdu
{
    public readonly byte Cla, Ins, P1, P2;
    public readonly byte[]? Data;
    public Apdu(byte cla, byte ins, byte p1, byte p2, byte[]? data = null)
    {
        Cla = cla; Ins = ins; P1 = p1; P2 = p2; Data = data;
    }
    public byte[] ToArray()
    {
        if (Data == null || Data.Length == 0)
            return new byte[] { Cla, Ins, P1, P2, 0x00 };
        byte[] apdu = new byte[5 + Data.Length];
        apdu[0] = Cla; apdu[1] = Ins; apdu[2] = P1; apdu[3] = P2; apdu[4] = (byte)Data.Length;
        Buffer.BlockCopy(Data, 0, apdu, 5, Data.Length);
        return apdu;
    }
}
readonly struct ApduResponse
{
    public readonly byte[] Data;
    public readonly ushort SW;
    public ApduResponse(byte[] data, ushort sw) { Data = data; SW = sw; }
}

static class WinSCard
{
    public const int SCARD_S_SUCCESS = 0;
    public const uint SCARD_SCOPE_USER = 0;
    public const uint SCARD_SHARE_SHARED = 2;
    public const uint SCARD_PROTOCOL_T0 = 0x0001;
    public const uint SCARD_PROTOCOL_T1 = 0x0002;
    public const uint SCARD_LEAVE_CARD = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct SCARD_IO_REQUEST
    {
        public uint dwProtocol;
        public uint cbPciLength;
    }

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    public static extern int SCardEstablishContext(uint dwScope, IntPtr notUsed1, IntPtr notUsed2, out IntPtr phContext);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    public static extern int SCardReleaseContext(IntPtr hContext);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    public static extern int SCardListReaders(IntPtr hContext, string? mszGroups, byte[]? mszReaders, ref uint pcchReaders);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    public static extern int SCardConnect(IntPtr hContext, string szReader, uint dwShareMode, uint dwPreferredProtocols,
                                          out IntPtr phCard, out uint pdwActiveProtocol);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    public static extern int SCardDisconnect(IntPtr hCard, uint dwDisposition);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    public static extern int SCardTransmit(IntPtr hCard, ref SCARD_IO_REQUEST pioSendPci,
                                           byte[] pbSendBuffer, int cbSendLength,
                                           ref SCARD_IO_REQUEST pioRecvPci,
                                           byte[] pbRecvBuffer, out uint pcbRecvLength);
}
#endregion
