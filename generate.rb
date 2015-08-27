#!/usr/bin/env ruby
# File to generate vulnerable RSA key under wiener attack
# email : w.zongyu@gmail.com
# Ref : https://en.wikipedia.org/wiki/Wiener's_attack

require 'openssl'
require 'base64'

class Gen
  def initialize(n=1024)
    @rsasafe = OpenSSL::PKey::RSA.new(n)
    e = setbade
    puts RSAtool.new(@rsasafe.params["p"], @rsasafe.params["q"], e).to_pem
  end

  def setbade
    rp = @rsasafe.params
    upper = (SqrtInt.sqrt(SqrtInt.sqrt(rp["n"].to_i).to_i)/3).to_i
    e = 0
    loop do
      begin 
        d = rand(1...upper)
        phin = (rp["p"]-1)*(rp["q"]-1)
        e = Invmod.invmod(d, phin.to_i)
        break
      rescue
      end
    end
    return e
  end
end

class RSAtool
  def initialize(p,q,e=65537)
    p,q = q,p if q>p
    @v = 0
    @p = p.to_i
    @q = q.to_i
    @n = @p*@q
    @e = e.to_i
    @d = Invmod.invmod(@e, ((@p-1)*(@q-1)))
    @exp1 = @d % (@p-1)
    @exp2 = @d % (@q-1)
    @coef = Invmod.invmod(@q, @p)
    version = OpenSSL::ASN1::Integer.new(@v)
    modulus = OpenSSL::ASN1::Integer.new(@n)
    publicExponent = OpenSSL::ASN1::Integer.new(@e)
    privateExponent = OpenSSL::ASN1::Integer.new(@d)
    prime1 = OpenSSL::ASN1::Integer.new(@p)
    prime2 = OpenSSL::ASN1::Integer.new(@q)
    exponent1 = OpenSSL::ASN1::Integer.new( @d % (@p-1))
    exponent2 = OpenSSL::ASN1::Integer.new( @d % (@q-1))
    coefficient = OpenSSL::ASN1::Integer.new( Invmod.invmod(@q, @p) )
    @seq = OpenSSL::ASN1::Sequence.new( [version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient] )
  end

  def to_der
    @seq.to_der
  end

  def to_pem
    header = "-----BEGIN RSA PRIVATE KEY-----\n" 
    tail = "-----END RSA PRIVATE KEY-----\n"
    return "#{header}#{Base64.encode64(@seq.to_der)}#{tail}"
  end

end

class Invmod
  def self.extended_gcd(a, b)
    last_remainder, remainder = a.abs, b.abs
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder != 0
      last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
      x, last_x = last_x - quotient*x, x
      y, last_y = last_y - quotient*y, y
    end
    return last_remainder, last_x * (a < 0 ? -1 : 1)
  end

  def self.invmod(e, et)
    g, x = extended_gcd(e, et)
    if g != 1
      raise 'Teh maths are broken!'
    end
    x % et
  end
end

class SqrtInt
  #REF http://stackoverflow.com/questions/15529205/ruby-sqrt-on-a-very-large-integer-cause-rounding-issues
  def self.sqrt a
    begv = 1
    endv = a
    while endv > begv + 1
       mid = (endv + begv)/2
       if mid ** 2 <= a
          begv = mid
       else
          endv = mid
       end
    end
    return begv
  end

  def self.is_square a
    return Math.sqrt(a).ceil == Math.sqrt(a).floor
  end
end

Gen.new(1024)
