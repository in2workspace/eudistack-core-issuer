package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the EUPL-1.2 library {@code nl.minvws.encoding.Base45} (0.0.3) wrote for these inputs, computed with it before
 * it was removed: {@link Base45Codec} must keep writing exactly the same, so a {@code cwt_vc} signed before and after
 * reads the same.
 */
class Base45CodecGoldenVectorsTest {

    private static final String EVERY_BYTE_VALUE = "100KB0*M0DY0W016C1PN1:Y1I12$C2BO2UZ2423ND3.O3G 3Z249E4SP42$4L35+E5EQ5X$5746QF60R6J%6%47CG7"
            + "VR75*7O58/G8HS8 *8A69TH93T9M+9-6AFIAYTA8-AR7B1JBKUB*-BD8CWJC6VCP.C:8DIKD$VDB/DU9E4LENWE./E"
            + "GAFZLF9XFS:F2BGLMG+XGE0HXBH7NHQYH01IJCI%NICZIV1J5DJOOJ/ZJH2K DKAPKT K33LMEL-PLF$LY3M8FMRQM"
            + "1%MK4N*FNDRNW%N65OPGO:ROI*O$5PBHPUSP4+PN6Q.HQGTQZ+Q97RSIR2URL-R+7SEJSXUS7.SQ8T0KTJVT%.TC9U"
            + "VKU5WUO/U/9VHLV WVA:VTAW";

    private static final String EVERY_BYTE_VALUE_BUT_ZERO = "X507H0QS00+0J61%H1CT1V+1572OI2/T2H-2 73AJ3TU33.3M84-J4FV4Y.4895RK51W5K/5*96DL6WW66:6PA7:L7"
            + "IX7$:7BB8UM84Y8N09.B9GN9ZY991ASCA2OALZA+1BEDBXOB7 BQ2C0ECJPC% CC3DVED5QDO$D/3EHFE QEA%ET4F"
            + "3GFMRF-%FF5GYGG8SGR*G16HKHH*SHD+HW6I6IIPTI:+II7J$IJBUJU-J48KNJK.UKG.KZ8L9KLSVL2/LL9M+KMEWM"
            + "X/M7ANQLN0XNJ:N%AOCMOVXO50POBP/MPHYP 0QACQTNQ3ZQM1R-CRFORYZR82SRDS1PSK S*2TDETWPT6$TP3U:EU"
            + "IQU$$UB4VUFV4RVN%V.4WU5";

    /** A zlib stream ("hello" deflated), the kind of input the signing of cwt_vc encodes. */
    private static final String DEFLATED_HELLO = "6BFKVPV0QSIP600GP5L0";

    @Test
    void everyByteValue_inOrder() {
        assertThat(Base45Codec.encode(everyByteValue())).isEqualTo(EVERY_BYTE_VALUE);
        assertThat(Base45Codec.decode(EVERY_BYTE_VALUE)).isEqualTo(everyByteValue());
    }

    @Test
    void anOddLength_endsWithTwoCharacters() {
        byte[] butZero = Arrays.copyOfRange(everyByteValue(), 1, 256);

        assertThat(Base45Codec.encode(butZero)).isEqualTo(EVERY_BYTE_VALUE_BUT_ZERO);
        assertThat(Base45Codec.decode(EVERY_BYTE_VALUE_BUT_ZERO)).isEqualTo(butZero);
    }

    @Test
    void aDeflatedStream() {
        byte[] deflated = {(byte) 0x78, (byte) 0x9C, (byte) 0xCB, (byte) 0x48, (byte) 0xCD, (byte) 0xC9, (byte) 0xC9,
                (byte) 0x07, (byte) 0x00, (byte) 0x06, (byte) 0x2C, (byte) 0x02, (byte) 0x15};

        assertThat(Base45Codec.encode(deflated)).isEqualTo(DEFLATED_HELLO);
    }

    private static byte[] everyByteValue() {
        byte[] bytes = new byte[256];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) i;
        }
        return bytes;
    }
}
