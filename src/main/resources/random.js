/*
 * Copyright (c) 2014  Simon Massey
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
/*
This module tries to use window.crypto random number generator which is available 
in modern browsers. If it cannot find that then it falls back to using an isaac 
random number generator which is seeded by Math.random. Then to improve security
it will skip forward until some time has passed. This will make the amount of 
randoms skipped determined by hardware/browser/load. Finally you can attach the skip
method to html input boxes with random16byteHex.advance(Math.floor(event.keyCode/4));
which will further advance the stream an unpredicatable amount. If the browser 
has built in crypto randoms the method call with do nothing. 
*/
var random16byteHex = (function() {
  function random() {
    var wordCount = 4;
    var randomWords;

    // First we're going to try to use a built-in CSPRNG
    if (typeof(window) != 'undefined' && window.crypto && window.crypto.getRandomValues) {
        randomWords = new Int32Array(wordCount);
        window.crypto.getRandomValues(randomWords);
    }
    // Because of course IE calls it msCrypto instead of being standard
    else if (typeof(window) != 'undefined' && window.msCrypto && window.msCrypto.getRandomValues) {
        randomWords = new Int32Array(wordCount);
        window.msCrypto.getRandomValues(randomWords);
    }
    // Last resort - we'll use isaac.js to get a random number. 
    else {
        randomWords = [];
        for (var i = 0; i < wordCount; i++) {
            randomWords.push(isaac.rand());
        }
    }
    
    var string = '';
    
    for( var i=0; i<wordCount; i++ ) {
      var int32 = randomWords[i];
      if( int32 < 0 ) int32 = -1 * int32;
      string = string + int32.toString(16);
    }

    return string;
  };
  	
  function isCrypto() {
    if (typeof(window) != 'undefined' && window.crypto && window.crypto.getRandomValues) {
      return true;
    }
    else if (typeof(window) != 'undefined' && window.msCrypto && window.msCrypto.getRandomValues) {
      return true;
    } else {
      return false;
    }
  };
  
  var crypto = isCrypto();
  
  /**
  Run this within onkeyup of web inputs as:
  random16byteHex.advance(Math.floor(event.keyCode/4));
  */
  function advance(ms) {
    if( !crypto ) {
      var start = Date.now();
      var end = start + ms;
      var now = Date.now();
      while( now < end ) {
          var t = now % 2;
          isaac.prng(1+t);
          now = Date.now();
      }
    }
  }
  
  return {
    'random' : random,
    'isCrypto' : crypto,
    'advance' : advance 
  };
})();

// if using isaac in a browser without crypto secure numbers spend 100ms advancing the stream
var random16byteHexAdvance = 100;

// optional override during unit tests
if( typeof test_random16byteHexAdvance != 'undefined' ) {
	random16byteHexAdvance = test_random16byteHexAdvance;
}

random16byteHex.advance(random16byteHexAdvance);
