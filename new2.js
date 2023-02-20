function Ot() {
                if (null == pt) {
                    for (pt = dt(); ht < mt; ) {
                        var e = Math.floor(65536 * Math.random());
                        vt[ht++] = 255 & e
                    }
                    for (pt.init(vt),
                    ht = 0; ht < vt.length; ++ht)
                        vt[ht] = 0;
                    ht = 0
                }
                return pt.next()
            }
            function jt(e) {
                var t;
                for (t = 0; t < e.length; ++t)
                    e[t] = Ot()
            }
            function Et() {}
            function Ct(e, t) {
                return new r(e,t)
            }
            function xt(e, t) {
                if (t < e.length + 11)
                    return console.error("Message too long for RSA"),
                    null;
                for (var n = new Array, a = e.length - 1; a >= 0 && t > 0; ) {
                    var o = e.charCodeAt(a--);
                    o < 128 ? n[--t] = o : o > 127 && o < 2048 ? (n[--t] = 63 & o | 128,
                    n[--t] = o >> 6 | 192) : (n[--t] = 63 & o | 128,
                    n[--t] = o >> 6 & 63 | 128,
                    n[--t] = o >> 12 | 224)
                }
                n[--t] = 0;
                for (var i = new Et, c = new Array; t > 2; ) {
                    for (c[0] = 0; 0 == c[0]; )
                        i.nextBytes(c);
                    n[--t] = c[0]
                }
                return n[--t] = 2,
                n[--t] = 0,
                new r(n)
            }
            function wt() {
                this.n = null,
                this.e = 0,
                this.d = null,
                this.p = null,
                this.q = null,
                this.dmp1 = null,
                this.dmq1 = null,
                this.coeff = null
            }
            function kt(e, t) {
                null != e && null != t && e.length > 0 && t.length > 0 ? (this.n = Ct(e, 16),
                this.e = parseInt(t, 16)) : console.error("Invalid RSA public key")
            }
            function Nt(e) {
                return e.modPowInt(this.e, this.n)
            }
            function St(e) {
                var t = xt(e, this.n.bitLength() + 7 >> 3);
                if (null == t)
                    return null;
                var n = this.doPublic(t);
                if (null == n)
                    return null;
                var r = n.toString(16);
                return 0 == (1 & r.length) ? r : "0" + r
            }
            function Pt(e, t) {
                for (var n = e.toByteArray(), r = 0; r < n.length && 0 == n[r]; )
                    ++r;
                if (n.length - r != t - 1 || 2 != n[r])
                    return null;
                for (++r; 0 != n[r]; )
                    if (++r >= n.length)
                        return null;
                for (var a = ""; ++r < n.length; ) {
                    var o = 255 & n[r];
                    o < 128 ? a += String.fromCharCode(o) : o > 191 && o < 224 ? (a += String.fromCharCode((31 & o) << 6 | 63 & n[r + 1]),
                    ++r) : (a += String.fromCharCode((15 & o) << 12 | (63 & n[r + 1]) << 6 | 63 & n[r + 2]),
                    r += 2)
                }
                return a
            }
            function Mt(e, t, n) {
                null != e && null != t && e.length > 0 && t.length > 0 ? (this.n = Ct(e, 16),
                this.e = parseInt(t, 16),
                this.d = Ct(n, 16)) : console.error("Invalid RSA private key")
            }
            function Tt(e, t, n, r, a, o, i, c) {
                null != e && null != t && e.length > 0 && t.length > 0 ? (this.n = Ct(e, 16),
                this.e = parseInt(t, 16),
                this.d = Ct(n, 16),
                this.p = Ct(r, 16),
                this.q = Ct(a, 16),
                this.dmp1 = Ct(o, 16),
                this.dmq1 = Ct(i, 16),
                this.coeff = Ct(c, 16)) : console.error("Invalid RSA private key")
            }
            function Rt(e, t) {
                var n = new Et
                  , a = e >> 1;
                this.e = parseInt(t, 16);
                for (var o = new r(t,16); ; ) {
                    for (; this.p = new r(e - a,1,n),
                    0 != this.p.subtract(r.ONE).gcd(o).compareTo(r.ONE) || !this.p.isProbablePrime(10); )
                        ;
                    for (; this.q = new r(a,1,n),
                    0 != this.q.subtract(r.ONE).gcd(o).compareTo(r.ONE) || !this.q.isProbablePrime(10); )
                        ;
                    if (this.p.compareTo(this.q) <= 0) {
                        var i = this.p;
                        this.p = this.q,
                        this.q = i
                    }
                    var c = this.p.subtract(r.ONE)
                      , l = this.q.subtract(r.ONE)
                      , s = c.multiply(l);
                    if (0 == s.gcd(o).compareTo(r.ONE)) {
                        this.n = this.p.multiply(this.q),
                        this.d = o.modInverse(s),
                        this.dmp1 = this.d.mod(c),
                        this.dmq1 = this.d.mod(l),
                        this.coeff = this.q.modInverse(this.p);
                        break
                    }
                }
            }
            function Dt(e) {
                if (null == this.p || null == this.q)
                    return e.modPow(this.d, this.n);
                for (var t = e.mod(this.p).modPow(this.dmp1, this.p), n = e.mod(this.q).modPow(this.dmq1, this.q); t.compareTo(n) < 0; )
                    t = t.add(this.p);
                return t.subtract(n).multiply(this.coeff).mod(this.p).multiply(this.q).add(n)
            }
            function It(e) {
                var t = Ct(e, 16)
                  , n = this.doPrivate(t);
                return null == n ? null : Pt(n, this.n.bitLength() + 7 >> 3)
            }
