package keysdk;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * 最小 EC 仿射點運算，只為一件事：由給定的私鑰純量算出對應公鑰。
 * JDK 標準庫沒有提供「私鑰 → 公鑰」的公開 API，而測試向量需要重現固定密文。
 */
final class EcMath {

    private EcMath() {
    }

    static ECPoint multiply(BigInteger k, ECPoint g, ECParameterSpec spec) {
        BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
        ECPoint result = null;
        ECPoint addend = g;
        BigInteger n = k;
        while (n.signum() > 0) {
            if (n.testBit(0)) {
                result = add(result, addend, spec, p);
            }
            addend = add(addend, addend, spec, p);
            n = n.shiftRight(1);
        }
        if (result == null) {
            throw new KeyError(KeyError.KEY, "私鑰純量為 0");
        }
        return result;
    }

    private static ECPoint add(ECPoint a, ECPoint b, ECParameterSpec spec, BigInteger p) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        BigInteger ax = a.getAffineX();
        BigInteger ay = a.getAffineY();
        BigInteger bx = b.getAffineX();
        BigInteger by = b.getAffineY();

        if (ax.equals(bx)) {
            if (!ay.equals(by) || ay.signum() == 0) {
                return null; // 無窮遠點
            }
            return doublePoint(a, spec, p);
        }
        BigInteger lambda = by.subtract(ay).multiply(bx.subtract(ax).modInverse(p)).mod(p);
        BigInteger x3 = lambda.multiply(lambda).subtract(ax).subtract(bx).mod(p);
        BigInteger y3 = lambda.multiply(ax.subtract(x3)).subtract(ay).mod(p);
        return new ECPoint(x3, y3);
    }

    private static ECPoint doublePoint(ECPoint a, ECParameterSpec spec, BigInteger p) {
        BigInteger x = a.getAffineX();
        BigInteger y = a.getAffineY();
        BigInteger aCoef = spec.getCurve().getA();
        BigInteger num = x.multiply(x).multiply(BigInteger.valueOf(3)).add(aCoef).mod(p);
        BigInteger den = y.multiply(BigInteger.valueOf(2)).mod(p).modInverse(p);
        BigInteger lambda = num.multiply(den).mod(p);
        BigInteger x3 = lambda.multiply(lambda).subtract(x.shiftLeft(1)).mod(p);
        BigInteger y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(p);
        return new ECPoint(x3, y3);
    }
}
