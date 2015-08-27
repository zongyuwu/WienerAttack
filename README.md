# WienerAttack
The Wiener's attack, named after cryptologist Michael J. Wiener, is a type of cryptographic attack against RSA. The attack uses the continued fraction method to expose the private key d when d is small.

Ref 
[http://www.math.ucla.edu/~gschaeff/crypto/RSAAttacks.pdf](http://www.math.ucla.edu/~gschaeff/crypto/RSAAttacks.pdf)  
[http://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf](http://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)  
[http://hacktracking.blogspot.tw/2014/10/wieners-attack-against-rsa-small-values.html](http://hacktracking.blogspot.tw/2014/10/wieners-attack-against-rsa-small-values.html)  

How to Use
  * wiener_api.rb, the api to use, Usage: `p,q = WienerExp.new(n, e).exploit`  
  * wiener.rb, the tool to use, Usage: `./wiener.rb -n N -e E` or `./wiener.rb -f pub.pem -t pem` 
  * generate.rb, the tool to generate vulnerable, Usage: ./generate.rb  
