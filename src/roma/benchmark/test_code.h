/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file has code that will be executed as part of benchmarking for both
// KV and BA servers.

#include <string_view>

namespace google::scp::roma::benchmark {

constexpr std::string_view kCodeHelloWorld = "hello = () => 'Hello world!';";
constexpr std::string_view kHandlerNameHelloWorld = "hello";

// This JS function is deliberately something that's expensive to run.  The
// code is based on:
// https://www.tutorialspoint.com/using-sieve-of-eratosthenes-to-find-primes-javascript
constexpr std::string_view kCodePrimeSieve = R"(
  function sieve() {
    // Find all prime numbers less than this:
    const n = 100000;
    // Create a boolean array of size n+1
    const primes = new Array(n + 1).fill(true);
    // Set first two values to false
    primes[0] = false;
    primes[1] = false;
    // Loop through the elements
    for (let i = 2; i <= Math.sqrt(n); i++) {
       if (primes[i]) {
          for (let j = i * i; j <= n; j += i) {
             primes[j] = false;
          }
       }
    }

    const result = [];
    // Loop through the array from 2 to n
    for (let i = 2; i <= n; i++) {
       if (primes[i]) {
          result.push(i);
       }
    }

    return result;
  }
)";
constexpr std::string_view kHandlerNamePrimeSieve = "sieve";

// This code was fetched from this publicly available URL on 2023-10-16:
// https://storage.googleapis.com/buyer-bas-dev/generateBid.js
constexpr std::string_view kCodeGoogleAdManagerGenerateBid = R"(
(function(stc){/*

 Copyright The Closure Library Authors.
 SPDX-License-Identifier: Apache-2.0
*/
var ea={},fa=this||self;function ha(a,b){return Error(`Invalid wire type: ${a} (at position ${b})`)}function ia(){return Error("Failed to read varint, encoding is invalid.")}function ja(a,b){return Error(`Tried to read past the end of the data ${b} > ${a}`)};var ka,la;a:{for(var ma=["CLOSURE_FLAGS"],na=fa,oa=0;oa<ma.length;oa++)if(na=na[ma[oa]],null==na){la=null;break a}la=na}var pa=la&&la[610401301];ka=null!=pa?pa:!1;var ra;const ua=fa.navigator;ra=ua?ua.userAgentData||null:null;function va(a){return ka?ra?ra.brands.some(({brand:b})=>b&&-1!=b.indexOf(a)):!1:!1}function n(a){var b;a:{if(b=fa.navigator)if(b=b.userAgent)break a;b=""}return-1!=b.indexOf(a)};function wa(){return ka?!!ra&&0<ra.brands.length:!1}function xa(){return wa()?va("Chromium"):(n("Chrome")||n("CriOS"))&&!(wa()?0:n("Edge"))||n("Silk")};!n("Android")||xa();xa();n("Safari")&&(xa()||(wa()?0:n("Coast"))||(wa()?0:n("Opera"))||(wa()?0:n("Edge"))||(wa()?va("Microsoft Edge"):n("Edg/"))||wa()&&va("Opera"));var ya={},za=null,Ba=function(a){var b=[];Aa(a,function(c){b.push(c)});return b},Aa=function(a,b){function c(k){for(;d<a.length;){var m=a.charAt(d++),r=za[m];if(null!=r)return r;if(!/^[\s\xa0]*$/.test(m))throw Error("Unknown base64 encoding at char: "+m);}return k}Ca();for(var d=0;;){var e=c(-1),f=c(0),h=c(64),g=c(64);if(64===g&&-1===e)break;b(e<<2|f>>4);64!=h&&(b(f<<4&240|h>>2),64!=g&&b(h<<6&192|g))}},Ca=function(){if(!za){za={};for(var a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(""),b=["+/=","+/","-_=","-_.","-_"],c=0;5>c;c++){var d=a.concat(b[c].split(""));ya[c]=d;for(var e=0;e<d.length;e++){var f=d[e];void 0===za[f]&&(za[f]=e)}}}};function Da(a){let b="",c=0;const d=a.length-10240;for(;c<d;)b+=String.fromCharCode.apply(null,a.subarray(c,c+=10240));b+=String.fromCharCode.apply(null,c?a.subarray(c):a);return btoa(b)}const Ea=/[-_.]/g,Fa={"-":"+",_:"/",".":"="};function Ha(a){return Fa[a]||""}function Ia(a){Ea.test(a)&&(a=a.replace(Ea,Ha));a=atob(a);const b=new Uint8Array(a.length);for(let c=0;c<a.length;c++)b[c]=a.charCodeAt(c);return b}function Ja(a){return null!=a&&a instanceof Uint8Array}let Na;var Oa={};let Pa;function Qa(a){if(a!==Oa)throw Error("illegal external caller");}var Sa=function(){return Pa||(Pa=new Ra(null,Oa))},Ta=function(a){const b=a.g;return null==b?"":"string"===typeof b?b:a.g=Da(b)},Ra=class{constructor(a,b){Qa(b);this.g=a;if(null!=a&&0===a.length)throw Error("ByteString should be constructed with non-empty values");}};function Ua(a){return 0==a.length?Sa():new Ra(a,Oa)};function Va(a){if("string"===typeof a)return{buffer:Ia(a),K:!1};if(Array.isArray(a))return{buffer:new Uint8Array(a),K:!1};if(a.constructor===Uint8Array)return{buffer:a,K:!1};if(a.constructor===ArrayBuffer)return{buffer:new Uint8Array(a),K:!1};if(a.constructor===Ra){Qa(Oa);var b=a.g;b=null==b||Ja(b)?b:"string"===typeof b?Ia(b):null;return{buffer:(null==b?b:a.g=b)||Na||(Na=new Uint8Array(0)),K:!0}}if(a instanceof Uint8Array)return{buffer:new Uint8Array(a.buffer,a.byteOffset,a.byteLength),K:!1};throw Error("Type not convertible to a Uint8Array, expected a Uint8Array, an ArrayBuffer, a base64 encoded string, a ByteString or an Array of numbers");};var Wa=function(a,b,{ma:c=!1}={}){a.ma=c;b&&(b=Va(b),a.h=b.buffer,a.A=b.K,a.l=0,a.i=a.h.length,a.g=a.l)},Xa=function(a,b){a.g=b;if(b>a.i)throw ja(a.i,b);},Ya=function(a){const b=a.h;let c=a.g,d=b[c++],e=d&127;if(d&128&&(d=b[c++],e|=(d&127)<<7,d&128&&(d=b[c++],e|=(d&127)<<14,d&128&&(d=b[c++],e|=(d&127)<<21,d&128&&(d=b[c++],e|=d<<28,d&128&&b[c++]&128&&b[c++]&128&&b[c++]&128&&b[c++]&128&&b[c++]&128)))))throw ia();Xa(a,c);return e},Za=class{constructor(a,b){this.h=null;this.A=!1;this.g=this.i=this.l=0;Wa(this,a,b)}},$a=[];var ab=function(a,{ra:b=!1}={}){a.ra=b},bb=function(a){var b=a.g;if(b.g==b.i)return!1;a.i=a.g.g;var c=Ya(a.g)>>>0;b=c>>>3;c&=7;if(!(0<=c&&5>=c))throw ha(c,a.i);if(1>b)throw Error(`Invalid field number: ${b} (at position ${a.i})`);a.A=b;a.h=c;return!0},cb=function(a){switch(a.h){case 0:if(0!=a.h)cb(a);else a:{a=a.g;var b=a.g;const c=b+10,d=a.h;for(;b<c;)if(0===(d[b++]&128)){Xa(a,b);break a}throw ia();}break;case 1:a=a.g;Xa(a,a.g+8);break;case 2:2!=a.h?cb(a):(b=Ya(a.g)>>>0,a=a.g,Xa(a,a.g+b));break;case 5:a=a.g;Xa(a,a.g+4);break;case 3:b=a.A;do{if(!bb(a))throw Error("Unmatched start-group tag: stream EOF");if(4==a.h){if(a.A!=b)throw Error("Unmatched end-group tag");break}cb(a)}while(1);break;default:throw ha(a.h,a.i);}},db=class{constructor(a,b){if($a.length){const c=$a.pop();Wa(c,a,b);a=c}else a=new Za(a,b);this.g=a;this.i=this.g.g;this.h=this.A=-1;ab(this,b)}},eb=[];class fb{constructor(a){this.g=a}};const q=Symbol();function t(a,b){q?a[q]|=b:void 0!==a.g?a.g|=b:Object.defineProperties(a,{g:{value:b,configurable:!0,writable:!0,enumerable:!1}})}function gb(a){const b=u(a);1!==(b&1)&&(Object.isFrozen(a)&&(a=Array.prototype.slice.call(a)),x(a,b|1))}function hb(a,b){q?a[q]&&(a[q]&=~b):void 0!==a.g&&(a.g&=~b)}function u(a){let b;q?b=a[q]:b=a.g;return b|0}function x(a,b){q?a[q]=b:void 0!==a.g?a.g=b:Object.defineProperties(a,{g:{value:b,configurable:!0,writable:!0,enumerable:!1}});return a}function ib(a,b){Object.isFrozen(a)&&(a=Array.prototype.slice.call(a));x(a,b);return a}function jb(a){t(a,1);return a}function kb(a){t(a,16);return a}function lb(a,b){x(b,(a|0)&-51)}function mb(a,b){x(b,(a|18)&-41)};var nb={};function ob(a){return null!==a&&"object"===typeof a&&!Array.isArray(a)&&a.constructor===Object}function pb(a,b){if(null!=a)if("string"===typeof a)a=a?new Ra(a,Oa):Sa();else if(a.constructor!==Ra){var c;Ja(a)?c=b?Ua(a):a.length?new Ra(new Uint8Array(a),Oa):Sa():c=void 0;a=c}return a}var qb=Object.freeze(x([],23));function rb(a){if(u(a.j)&2)throw Error();};function sb(a){if("number"!==typeof a)throw Error(`Value of float/double field must be a number, found ${typeof a}: ${a}`);return a}function tb(a){if(null==a)return a;if("number"===typeof a||"NaN"===a||"Infinity"===a||"-Infinity"===a)return Number(a)}function ub(a){if(null==a)return a;switch(typeof a){case "string":return+a;case "number":return a}}function vb(a){if(null==a)return a;switch(typeof a){case "string":return+a;case "number":return a}}function wb(a){return a}function xb(a){return null==a?a:a}function yb(a){return a}function zb(a){return a}function Ab(a,b,c){var d=!1;if(null!=a&&"object"===typeof a&&!(d=Array.isArray(a))&&a.V===nb)return a;if(d){var e=d=u(a);0===e&&(e|=c&16);e|=c&2;e!==d&&x(a,e);return new b(a)}}const Bb=Symbol();var z=function(a,b,c){return-1===b?null:b>=a.O?a.A?a.A[b]:void 0:c&&a.A&&(c=a.A[b],null!=c)?c:a.j[b+-1]},A=function(a,b,c,d){a.pa&&(a.pa=void 0);if(b>=a.O||d)return d=a.O+-1,(a.A||(a.A=a.j[d]={}))[b]=c,a;a.j[b+-1]=c;(c=a.A)&&b in c&&delete c[b];return a};function Cb(a,b,c,d){let e=z(a,b);Array.isArray(e)||(e=qb);const f=u(e);f&1||jb(e);if(d)f&2||t(e,18),c&1||Object.freeze(e);else{d=!(c&2);const h=f&2;c&1||!h?d&&f&16&&!h&&hb(e,16):(e=jb(Array.prototype.slice.call(e)),A(a,b,e))}return e}function B(a,b,c){const d=!!(u(a.j)&2);let e=Cb(a,b,1,d),f=u(e);if(!(f&4)){Object.isFrozen(e)&&(e=jb(e.slice()),A(a,b,e));let h=0,g=0;for(;h<e.length;h++){const k=c(e[h]);null!=k&&(e[g++]=k)}g<h&&(e.length=g);f|=5;d&&(f|=18);x(e,f);f&2&&Object.freeze(e)}!d&&(f&2||Object.isFrozen(e))&&(e=Array.prototype.slice.call(e),t(e,5),A(a,b,e));return e}var C=function(a,b){return B(a,b,tb)};function Db(a){return pb(a,!0)}function Eb(a){return pb(a,!1)}function Fb(a,b,c,d){if(null==c)return rb(a),A(a,b);const e=u(c);if(!(e&4)){if(e&2||Object.isFrozen(c))c=Array.prototype.slice.call(c);for(let f=0;f<c.length;f++)c[f]=d(c[f]);x(c,e|5)}rb(a);return A(a,b,c)}function E(a,b,c,d){rb(a);c!==d?A(a,b,c):A(a,b,void 0,!1);return a}var F=function(a,b,c){if(null!=c&&"number"!==typeof c)throw Error(`Value of float/double field must be a number|null|undefined, found ${typeof c}: ${c}`);return E(a,b,c,0)},Nb=function(){var a=Gb,b=Hb;let c=0;for(let d=0;d<b.length;d++){const e=b[d];null!=z(a,e)&&(0!==c&&A(a,c,void 0,!1),c=e)}return c},Ob=function(a,b,c){const d=z(a,c,!1);b=Ab(d,b,u(a.j));b!==d&&null!=b&&A(a,c,b,!1);return b},G=function(a,b,c){(a=Ob(a,b,c))?b=a:(a=b[Bb])?b=a:(a=new b,t(a.j,18),b=b[Bb]=a);return b},H=function(a,b,c){b=Ob(a,b,c);if(null==b)return b;if(!(u(a.j)&2)){const d=Pb(b);d!==b&&(b=d,A(a,c,b,!1))}return b},Rb=function(a,b,c){return Qb(a,b,c,1,u(a.j))};function Qb(a,b,c,d,e){var f=!!(e&2),h=Cb(a,c,1,f);if(h===qb||!(u(h)&4)){var g=h;h=!!(e&2);var k=!!(u(g)&2);f=g;!h&&k&&(g=Array.prototype.slice.call(g));var m=e|(k?2:0);e=k||void 0;let r=k=0;for(;k<g.length;k++){const y=Ab(g[k],b,m);void 0!==y&&(e=e||!!(2&u(y.j)),g[r++]=y)}r<k&&(g.length=r);b=g;g=u(b);m=g|5;e=e?m&-9:m|8;g!=e&&(b=ib(b,e));g=b;f!==g&&A(a,c,g);(h&&2!==d||1===d)&&Object.freeze(g);return g}if(3===d)return h;f||(f=Object.isFrozen(h),1===d?f||Object.freeze(h):(d=u(h),b=d&-19,f&&(h=Array.prototype.slice.call(h),d=0,A(a,c,h)),d!==b&&x(h,b)));return h}var I=function(a,b,c){const d=u(a.j);var e=!!(d&2);a=Qb(a,b,c,e?1:2,d);if(!(e||u(a)&8)){for(e=0;e<a.length;e++)b=a[e],c=Pb(b),b!==c&&(a[e]=c);t(a,8)}return a},J=function(a,b,c){rb(a);null==c&&(c=void 0);return A(a,b,c)};function Sb(a,b,c,d){const e=u(a.j);if(e&2)throw Error();a=Qb(a,c,b,2,e);c=null!=d?d:new c;a.push(c);c.K()&&hb(a,8);return c}function L(a,b){return null==a?b:a}var M=function(a,b){a=z(a,b);return L(null==a?a:!!a,!1)},N=function(a,b){return L(ub(z(a,b)),0)},Tb=function(a,b){return L(vb(z(a,b)),0)},O=function(a,b){return L(z(a,b),"0")},P=function(a,b){const c=z(a,b),d=tb(c);null!=d&&d!==c&&A(a,b,d);return L(d,0)},Q=function(a,b){return L(z(a,b),"")},R=function(a,b){return L(xb(z(a,b)),0)};let Ub;function Vb(a,b){Ub=b;a=new a(b);Ub=void 0;return a};function Wb(a){switch(typeof a){case "number":return isFinite(a)?a:String(a);case "boolean":return a?1:0;case "object":if(a&&!Array.isArray(a)){if(Ja(a))return Da(a);if(a instanceof Ra)return Ta(a)}}return a};function Xb(a,b){const c=Array.prototype.slice.call(a.j),d=a.A;var e=c.length+(d?-1:0);let f=0;for(;f<e;f++)c[f]=b(c[f]);if(d){e=c[f]={};for(const h in d)Object.prototype.hasOwnProperty.call(d,h)&&(e[h]=b(d[h]))}b=Vb(a.constructor,kb(c));a.ha&&(b.ha=a.ha.slice());return b}function Yb(a,b,c,d,e,f){if(null!=a){if(Array.isArray(a))a=e&&0==a.length&&u(a)&1?void 0:f&&u(a)&2?a:Zb(a,b,c,void 0!==d,e,f);else if(ob(a)){const h={};for(let g in a)Object.prototype.hasOwnProperty.call(a,g)&&(h[g]=Yb(a[g],b,c,d,e,f));a=h}else a=b(a,d);return a}}function Zb(a,b,c,d,e,f){const h=d||c?u(a):0;d=d?!!(h&16):void 0;a=Array.prototype.slice.call(a);for(let g=0;g<a.length;g++)a[g]=Yb(a[g],b,c,d,e,f);c&&c(h,a);return a}function $b(a){return a.V===nb?a.toJSON():Wb(a)};function ac(a,b,c=mb){if(null!=a){if(a instanceof Uint8Array)return b?a:new Uint8Array(a);if(Array.isArray(a)){const d=u(a);if(d&2)return a;if(b&&!(d&32)&&(d&16||0===d))return x(a,d|18),a;a=Zb(a,ac,d&4?mb:c,!0,!1,!0);bc(a);return a}a.V===nb&&(u(a.j)&2||(a=cc(a,!0),t(a.j,18)));return a}}function cc(a,b){const c=u(a.j),d=b||c&2?mb:lb,e=!!(c&16);return Xb(a,f=>ac(f,e,d))}function dc(a){ec(a.j);return a}function ec(a){var b=u(a);if(!(b&2))for(x(a,b|2),b=0;b<a.length;b++){var c=a[b];if(c)if(Array.isArray(c))ec(c),bc(c);else if(c.V===nb)dc(c);else if(b===a.length-1&&ob(c))for(let d in c){if(!Object.prototype.hasOwnProperty.call(c,d))continue;const e=c[d];e&&(Array.isArray(e)?(ec(e),bc(e)):e.V===nb&&dc(e))}}}function Pb(a){if(!(u(a.j)&2))return a;const b=cc(a,!1);b.pa=a;return b}function bc(a){const b=u(a);b&4&&b&2&&Object.freeze(a)};var T=class{constructor(a){null==a&&(a=Ub);Ub=void 0;if(null==a)a=[],x(a,48);else{if(!Array.isArray(a))throw Error();t(a,32)}this.j=a;a:{var b=this.j.length;a=b-1;if(b&&(b=this.j[a],ob(b))){this.A=b;this.O=a- -1;break a}this.O=Number.MAX_VALUE}}toJSON(){var a=Zb(this.j,$b,void 0,void 0,!1,!1);return fc(this,a,!0)}K(){return!!(u(this.j)&2)}};T.prototype.V=nb;T.prototype.toString=function(){return fc(this,this.j,!1).toString()};function fc(a,b,c){const d=a?a.constructor.m:void 0;var e=a.O;if(d){if(!c){b=Array.prototype.slice.call(b);var f;if(b.length&&ob(f=b[b.length-1]))for(var h=0;h<d.length;h++)if(d[h]>=e){Object.assign(b[b.length-1]={},f);break}}e=b;c=!c;a=a.O;let k;for(f=0;f<d.length;f++)if(h=d[f],h<a){h+=-1;var g=e[h];null==g?e[h]=c?qb:jb([]):c&&g!==qb&&gb(g)}else{if(!k){let m;e.length&&ob(m=e[e.length-1])?k=m:e.push(k={})}g=k[h];null==k[h]?k[h]=c?qb:jb([]):c&&g!==qb&&gb(g)}}return b}function gc(a,b){if(null==b)return new a;if(!Array.isArray(b))throw Error("must be an array");if(Object.isFrozen(b)||Object.isSealed(b)||!Object.isExtensible(b))throw Error("arrays passed to jspb constructors must be mutable");t(b,64);return Vb(a,kb(b))};const hc=Symbol();function ic(a){let b=a[hc];if(!b){const c=jc(a),d=c.i;b=d?(e,f)=>d(e,f,c):(e,f)=>{for(;bb(f)&&4!=f.h;){var h=f.A,g=c[h];if(!g){var k=c.h;k&&(k=k[h])&&(g=c[h]=kc(k))}if(!g||!g(f,e,h))if(k=f,h=e,g=k.i,cb(k),!k.ra){var m=k.g.g-g;k.g.g=g;k=k.g;g=m;if(0==g)g=Sa();else{if(0>g)throw Error(`Tried to read a negative byte length: ${g}`);m=k.g;var r=m+g;if(r>k.i)throw ja(g,k.i-m);k.g=r;r=m;k.ma&&k.A?g=k.h.subarray(r,r+g):(k=k.h,m=r,g=r+g,g=m===g?Na||(Na=new Uint8Array(0)):k.slice(m,g));g=Ua(g)}(k=h.ha)?k.push(g):h.ha=[g]}}return e};a[hc]=b}return b}function lc(a){if(a=a.za)return ic(a)}function kc(a){const b=lc(a),c=a.bb.g;if(b){const d=jc(a.za).g;return(e,f,h)=>c(e,f,h,d,b)}return(d,e,f)=>c(d,e,f)}function mc(a,b){let c=a[b];"function"==typeof c&&0===c.length&&(c=c(),a[b]=c);return Array.isArray(c)&&(nc in c||oc in c||0<c.length&&"function"==typeof c[0])?c:void 0}const oc=Symbol(),nc=Symbol();function pc(a,b){const c=a.g;return b?(d,e,f)=>c(d,e,f,b):c}function qc(a,b,c){const d=a.g,e=ic(b),f=jc(b).g;return(h,g,k)=>d(h,g,k,f,e,c)}function jc(a){var b=a[nc];if(b)return b;a:{b=a[nc]={};var c=pc,d=qc;b.g=a[0];let g=1;if(a.length>g&&"number"!==typeof a[g]){var e=a[g++];if(Array.isArray(e)){b.i=e[0];b.h=e[1];break a}b.h=e}for(;g<a.length;){e=a[g++];for(var f=g+1;f<a.length&&"number"!==typeof a[f];)f++;const k=a[g++];f-=g;switch(f){case 0:b[e]=c(k);break;case 1:(f=mc(a,g))?(g++,b[e]=d(k,f)):b[e]=c(k,a[g++]);break;case 2:f=b;var h=g++;h=mc(a,h);f[e]=d(k,h,a[g++]);break;default:throw Error("unexpected number of binary field arguments: "+f);}}}nc in a&&oc in a&&(a.length=0);return b}var rc;rc=new fb(function(a,b,c){if(0!==a.h)return!1;{var d=a.g;let f=0,h=a=0;const g=d.h;let k=d.g;do{var e=g[k++];f|=(e&127)<<h;h+=7}while(32>h&&e&128);32<h&&(a|=(e&127)>>4);for(h=3;32>h&&e&128;h+=7)e=g[k++],a|=(e&127)<<h;Xa(d,k);if(128>e){d=f>>>0;e=a>>>0;if(a=e&2147483648)d=~d+1>>>0,e=~e>>>0,0==d&&(e=e+1>>>0);d=4294967296*e+(d>>>0);a=a?-d:d}else throw ia();}A(b,c,a);return!0});var sc;sc=new fb(function(a,b,c){if(5!==a.h)return!1;a=a.g;var d=a.h;const e=a.g,f=d[e],h=d[e+1],g=d[e+2];d=d[e+3];Xa(a,a.g+4);A(b,c,(f<<0|h<<8|g<<16|d<<24)>>>0);return!0});function tc(a,b){const c=uc();if(!b(a))throw b=c?c()+"\n":"",Error(b+String(a));}function vc(a){tc(a,wc);return a}let xc=void 0;function uc(){const a=xc;xc=void 0;return a};function yc(a){return b=>{if(null==b||""==b)b=new a;else{b=JSON.parse(b);if(!Array.isArray(b))throw Error(void 0);b=Vb(a,kb(b))}return b}};function zc(a){return JSON.stringify([a.map(b=>[{[b.La]:b.Ja}])])};function Ac(a,b=`unexpected value ${a}!`){throw Error(b);};var Bc=function(a,...b){var c=encodeURIComponent,d=zc(b);b=[];for(var e=0,f=0;f<d.length;f++){var h=d.charCodeAt(f);255<h&&(b[e++]=h&255,h>>=8);b[e++]=h}d=3;void 0===d&&(d=0);Ca();d=ya[d];e=Array(Math.floor(b.length/3));f=d[64]||"";let g=0;for(h=0;g<b.length-2;g+=3){var k=b[g],m=b[g+1],r=b[g+2],y=d[k>>2];k=d[(k&3)<<4|m>>4];m=d[(m&15)<<2|r>>6];r=d[r&63];e[h++]=y+k+m+r}y=0;r=f;switch(b.length-g){case 2:y=b[g+1],r=d[(y&15)<<2]||f;case 1:b=b[g],e[h]=d[b>>2]+d[(b&3)<<4|y>>4]+r+f}c=c(e.join(""));a.g(`${"https://pagead2.googlesyndication.com/pagead/ping"}?e=${3}&d=${c}`)},Cc=class{constructor(a){this.g=a}};var Dc=function(a){return(b,c)=>{a:{if(eb.length){const f=eb.pop();ab(f,c);Wa(f.g,b,c);b=f}else b=new db(b,c);try{var d=jc(a).g;var e=ic(a)(new d,b);break a}finally{d=b,b=d.g,b.h=null,b.A=!1,b.l=0,b.i=0,b.g=0,b.ma=!1,d.A=-1,d.h=-1,100>eb.length&&eb.push(d)}e=void 0}return e}}([class extends T{},1,rc,2,sc,3,sc]);var Ec=class extends T{};var Fc=class extends T{constructor(){super()}};var Gc=class extends T{constructor(){super()}};Gc.m=[6];var Hc=class extends T{};Hc.m=[2,3,4];var Ic=class extends T{};Ic.m=[1];var Jc=class extends T{};Jc.m=[2];var Kc=class extends T{};Kc.m=[2];var Lc=class extends T{i(){return I(this,Kc,1)}g(){return I(this,Kc,3)}h(){return P(this,6)}l(){return R(this,9)}};Lc.m=[1,3,10,7,8];var Mc=class extends T{};Mc.m=[3];var Nc=class extends T{};var Oc=class extends T{};Oc.m=[2,3,5];var Pc=class extends T{};Pc.m=[3,4,9];var Qc=class extends T{};Qc.m=[3];var Rc=class extends T{};Rc.m=[3,4,5,6,7];var Sc=class extends T{};Sc.m=[1,2];var Tc=class extends T{constructor(){super()}};Tc.m=[15];var Uc=class extends T{};var Vc=class extends T{};Vc.m=[1];var Wc=class extends T{};var Xc=class extends T{};var Yc=class extends T{g(){return H(this,Lc,4)}h(){return H(this,Sc,5)}B(){return B(this,14,yb)}C(){return B(this,15,yb)}l(){return M(this,16)}i(){return I(this,Xc,17)}};Yc.m=[9,10,11,12,13,14,15,17];var Zc=class extends T{};Zc.m=[1];var $c=class extends T{};var ad=class extends T{h(){return I(this,Kc,1)}i(){return I(this,Kc,2)}g(){return I(this,Kc,3)}};ad.m=[1,2,3];var bd=class extends T{h(){return Q(this,1)}l(){return O(this,2)}g(){return O(this,3)}B(){return P(this,5)}C(){return O(this,6)}i(){return M(this,7)}};var cd=class extends T{g(){return P(this,1)}};var dd=class extends T{i(){return P(this,1)}l(){return P(this,2)}h(){return P(this,3)}C(){return P(this,4)}B(){return P(this,9)}g(){return H(this,cd,5)}D(){return P(this,6)}P(){return P(this,7)}L(){return P(this,8)}};var ed=class extends T{g(){return B(this,1,xb)}h(){return P(this,2)}i(){return C(this,3)}};ed.m=[1,3];var td=class extends T{};var ud=class extends T{g(){return M(this,1)}ka(){return M(this,2)}L(){return H(this,dd,3)}i(){return H(this,dd,4)}P(){return H(this,ed,11)}h(){return M(this,5)}ja(){return M(this,6)}l(){return M(this,7)}la(){return M(this,8)}xa(){return N(this,9)}wa(){return M(this,10)}C(){return M(this,14)}D(){return M(this,15)}B(){return M(this,16)}};var vd=class extends T{h(){return H(this,ud,3)}g(){return G(this,ud,3)}l(){return Q(this,4)}P(){return H(this,Sc,5)}ka(){return H(this,dd,6)}ja(){return H(this,dd,7)}L(){return H(this,ed,18)}D(){return P(this,8)}C(){return M(this,11)}i(){return H(this,bd,16)}la(){return G(this,bd,16)}B(){return N(this,17)}};vd.m=[2];var wd=class extends T{constructor(){super()}};wd.m=[10];var xd=class extends T{g(){return O(this,2)}};var yd=class extends T{};var zd=class extends T{};zd.m=[1];var Ad=class extends T{};var Bd=class extends T{l(){return Q(this,2)}B(){return Q(this,6)}C(){return M(this,4)}h(){return H(this,xd,5)}g(){return Q(this,11)}i(){return Q(this,19)}D(){return M(this,21)}},Cd=yc(Bd);function Dd(a,...b){Bc(a,...b.map(c=>({La:9,Ja:c.toJSON()})))};var wc=a=>Array.isArray(a);var Ed=function(a){return(b,c)=>dc(a(b,c))}(Dc);function Fd(a,b){return!b||0>=b?a:Math.min(a,b)}function V(a,b,c){return b?b:c?c:a?1:0}function Gd(a,b){return a&&0<a.length?a:b&&0<b.length?b:[]}function Hd(a){a=a?.l();return void 0===a?!1:[61,51,52].includes(a)};function Id(a,b){if(!b||0>=b)return{o:0,F:2};var c=a?.L(),d=a?.h()?.P(),e=a?.ja();if(!c&&!d){var f=a?.h()?.i();a=V(!0,e?.i(),f?.i());var h=V(!1,e?.l(),f?.l());c=V(!1,e?.h(),f?.h());e=V(!1,e?.g()?.g(),f?.g()?.g());f=new dd;d=F(f,1,a);d=F(d,2,h);d=F(d,3,c);var g=new cd;g=F(g,1,e);J(d,5,g);return{o:b*a*(1-1/(1+Math.exp(-h*(Math.log(b/1E6)-e-c)))),F:1,N:4,qa:f}}if(c||d){a=V(!1,c?.h(),d?.h());h=Gd(c?.i(),d?.i());c=Gd(c?.g(),d?.g());d=[];for(f of c)switch(f){case 1:d.push(1E-6*b);break;case 2:g=e?.g()?.g(),d.push("number"===typeof g?Math.exp(g):0)}e=Jd(h,d);1===e.F?(b=new ed,b=Fb(b,3,h,sb),b=Fb(b,1,c,wb),b=F(b,2,a),e.qa=b,b=e):b=0>=a||1<a?e:{o:b*a,F:e.F,N:9}}else b={o:0,F:3};return b}function Jd(a,b){if(0===a.length||0>a[0])return{o:0,F:5};const c=b.length;if(a.length!==1+2*(1+c))return{o:0,F:6};const d=c+2;let e=a[1],f=a[d];for(let h=0;h<c;h++){const g=1+h;if(0>=b[h]){if(1E-9>Math.abs(a[1+g])&&1E-9>Math.abs(a[d+g]))continue;return{o:0,F:4}}const k=Math.log(b[h]);e+=a[1+g]*k;f+=a[d+g]*k}return{o:1E9*Math.exp(-.5*(-(e+f)+Math.sqrt((e-f)*(e-f)+4*a[0]))),F:1,N:8}};function Kd(a,b){var c=a?.ka();const d=a?.h()?.L();if(!b||0>=b)return{o:0,N:1};if(1===a?.B())return{o:b,N:2};if(!a?.h()?.ka())return{o:.85*b,N:2};var e=V(!0,c?.C(),d?.C());const f=V(!0,c?.i(),d?.i()),h=V(!1,c?.l(),d?.l()),g=V(!1,c?.h(),d?.h()),k=V(!1,c?.g()?.g(),d?.g()?.g());var m=V(!1,c?.B(),d?.B());const r=new dd;var y=F(r,1,f);y=F(y,2,h);y=F(y,3,g);y=F(y,4,e);y=F(y,9,m);var Ga=new cd;Ga=F(Ga,1,k);J(y,5,Ga);y=3;e=e*b*f*(1-1/(1+Math.exp(-h*(Math.log(e*b/1E6)-k-g))));e<m*b&&(e=m*b,y=6);m=1E6*a?.D();c=c?.L()??0;a?.h()?.ja()&&e<m&&m<b&&(a=d?.P()??0,e=m+a*(0===c?Math.log(b/m):(b-m)/(c-m))*1E6,y=7);return{o:e,N:y,qa:r}};function Ld(a,b,c){if(!(0<C(a,2).length&&C(a,2).length===B(a,3,xb).length&&C(a,2).length===C(a,4).length))return 0;let d=0,e=0,f=1;for(const h of B(a,3,xb)){let g=0;switch(h){case 1:g=C(a,2)[e]*(b.W?Math.pow(b.W,C(a,4)[e]):0);break;case 2:d=g=C(a,2)[e]*(b.ia?Math.pow(b.ia,C(a,4)[e]):0);break;case 3:g=C(a,2)[e]}if(0===g)return 0;f*=g;e+=1}0<P(a,7)&&(b=1,0<c&&(b=c),f=Math.min(f,P(a,7)*b*d*1E3));return 1E6*f}function Md(a,b,c){let d=0;c&&(0<I(c,Hc,7).length?d=Ld(I(c,Hc,7)[0],a,b):0<I(c,Hc,8).length&&(d=Ld(I(c,Hc,8)[0],a,b)));return d};var Nd={Za:0,Ua:1,Pa:2,Ra:3,Qa:4,Va:5,Xa:6,ab:7,Ta:8,Na:9,Ya:10,Sa:11,Oa:12,Wa:13};function Od(a,b,c){if(R(a,2)!==R(b,2))return c;let d=!1;switch(R(a,2)){case 1:a:{var e=new Set(B(a,3,vb)??[]);for(var f of B(b,3,vb))if(e.has(f)){d=!0;break a}d=!1}break;case 0:a:{f=new Set(B(a,4,zb)??[]);for(e of B(b,4,zb))if(f.has(e)){d=!0;break a}d=!1}break;case 2:b=new Pd(b);d=(f=H(a,Oc,5))?Qd(b,f):!1;break;case 3:a:{f=new Set;for(const h of B(a,9,u(a.j)&18?Db:Eb))f.add(Ta(h));if(0===f.size)d=!0;else{for(const h of B(b,6,u(b.j)&18?Db:Eb))if(f.has(Ta(h))){d=!0;break a}d=!1}}break;case 4:d=Rd(a,b)}return M(a,6)?d?null:c:d?c:null}function Rd(a,b){a=H(a,Mc,10);if(void 0===a)return!1;var c=I(b,Qc,7);if(0===c.length)return!1;b=!0;for(const e of c)if(N(e,1)===N(a,1)&&N(e,2)===N(a,2)){b&&(b=!1);var d=B(e,3,ub);if(0===d.length)return!1;c=!0;for(const f of d){d=f;const h=Math.floor(d/32),g=B(a,3,vb);if(!(h>=g.length||0!==(g[h]>>>d%32)%2)){c=!1;break}}if(c)return!0}return b}function Qd(a,b){const c=R(b,1),d=I(b,Nc,3),e=I(b,Oc,2);let f;switch(c){case 2:f=d.every(h=>Sd(a,h))&&e.every(h=>Qd(a,h));break;case 1:f=d.some(h=>Sd(a,h))||e.some(h=>Qd(a,h));break;default:Ac(c)}return M(b,4)?!f:f}var Sd=function(a,b){const c=Tb(b,2);return(a=a.Y.get(Tb(b,1)))?a.has(c):!1};class Pd{constructor(a){this.Y=new Map;for(const b of I(a,Nc,5)){a=Tb(b,1);const c=Tb(b,2);let d=this.Y.get(a);d||(d=new Set,this.Y.set(a,d));d.add(c)}}};function Td(a,b){for(const c of b?.get(a)||[])if(c.count+1>c.Ia)return!1;return!0};function Ud(a){a=a.split("!");let b="-1";for(let c=0;c<a.length;c++)a[c].match(/^\dm\d+/)?c+=+a[c].substring(2):a[c].match(/^\d{2}m\d+/)?c+=+a[c].substring(3):a[c].match(/^1j\d+/)&&(b=a[c].substring(2));return b}function Vd(a,b){if(!a.Ga)return 1;const c=a.sa?.some(e=>b.va?.includes(e,0));var d=b.interestGroupName??void 0;if(void 0===d)return 10;d=Ud(d);if("-1"===d)return 11;a=a.sa?.includes(d,0);return c&&!a?10:1};function Wd(a,b){return null==a.oa?!0:!a.oa.some(c=>b.va?.includes(c,0))};function Xd({R:a,v:b,G:c,U:d}={}){return Yd(0,a?.h()??[],b?.i()??[],c??new Map,d??!1)}function Zd({R:a,v:b,G:c,U:d}={}){return Yd(1,a?.i()??[],b?.g()??[],c??new Map,d??!1)}function $d({R:a,v:b,G:c,U:d}={}){return Yd(1,a?.g()??[],b?.g()??[],c??new Map,d??!1)}function Yd(a,b,c,d,e){let f=0;const h=new Map;for(var g of b)h.set(Q(g,1),g),f=P(g,3);g=null;for(const k of c)if(f=P(k,3),e&&(f=ae(f,k,d)),b=h.get(Q(k,1))){a:{c=a;g=k;b=C(b,2);const m=C(g,2);if(b.length===m.length){g=0;for(let r=0;r<b.length;r++)g+=b[r]*m[r];b=g}else b=void 0;if(void 0!==b)switch(c){case 0:c=1/(1+Math.exp(-1*b));break a;case 1:c=Math.exp(b);break a}c=void 0}if(void 0!==c)return e&&(c=ae(c,k,d)),c;g=f}return g??f}function ae(a,b,c){const d=N(G(b,Jc,4),1);c=c.get(d);if(void 0===c||c>=Rb(G(b,Jc,4),Ic,2).length)return a;b=Rb(G(b,Jc,4),Ic,2)[c];return C(b,1).length?a*C(b,1)[0]:a};function be(a,b,c){"0"===a||c.has(a)||c.set(a,b.filter(d=>0<N(d,3)).map(d=>{let e=N(d,3);switch(R(d,1)){case 6:d=60*N(d,2);break;case 1:d=3600*N(d,2);break;case 2:d=86400*N(d,2);break;case 3:d=604800*N(d,2);break;case 4:d=2592E3*N(d,2);break;case 5:d=null;break;default:e=d=0}return{ua:d,Ia:e,count:0}}))}function ce(a,b,c){if(b=c.get(b))for(const d of b)(null===d.ua||N(a,1)<=d.ua)&&d.count++};var de=class extends T{};de.m=[2];var ee=class extends T{constructor(){super()}};ee.m=[2];function fe(a,b,c){c=I(c,de,2);var d=0;for(let h=c.length-1;0<=h;h--){d*=C(c[h],2).length+1;a:switch(R(c[h],1)){case 1:var e=a;var f=Ed(Ba(b.l()));f&&z(f,1)?(f=z(f,1),e=L(z(e,3),0),e=0===f||0===e||f<e?-1:(f-e)/6E7):e=-1;break a;default:e=-1}f=0;const g=C(c[h],2);for(;f<g.length&&!(e<g[f]);f++);d+=f}return d}function ge(){var a=new ee;a=E(a,1,0,0);var b=new de;b=E(b,1,1,0);b=Fb(b,2,[20],sb);Sb(a,2,de,b);return[a]};var he=class extends T{};he.m=[1];const ie={ad:{},bid:0,render:"",allowComponentAuction:!0};function je(a,b,c,d){b=b?new vd(vc(b)):void 0;if(!b||!I(b,td,2).length&&!b.g().g()&&!b.g().h())return ie;const e=new Vc(vc(a.userBiddingSignals)),f=a.ads.map(k=>({renderUrl:k.renderUrl,metadata:new Ec(vc(k.metadata))})),h=a.trustedBiddingSignalsKeys?a.trustedBiddingSignalsKeys[0]:void 0;let g;c&&h&&c[h]&&(g=gc(Zc,vc(c[h])));c=d.prevWins.map(k=>{var m=new Fc;m=E(m,1,k[0],0);k=new Ec(vc(k[1].metadata));return J(m,2,k)});return ke(a.name,e,f,d,c,g,b)}function ke(a,b,c,d,e,f,h){let g=null,k=null,m=null;if(h&&(M(G(h,$c,12),1)||M(G(h,$c,12),2))){var r=new wd;var y=E(r,2,0,0);var Ga=E(y,5,a,"");var te=E(Ga,7,!1,!1);var ue=J(te,8,h);g=E(ue,9,h.l(),"");const l=globalThis.forDebuggingOnly;M(G(h,$c,12),1)&&(k=new Cc(l.reportAdAuctionWin));M(G(h,$c,12),2)&&(m=new Cc(l.reportAdAuctionLoss));if(M(G(h,$c,12),5)){var ve=J(g,6,b),we=new Gc;var xe=E(we,1,d.topWindowHostname,"");var ye=E(xe,2,d.seller,"");var ze=E(ye,3,d.topLevelSeller,"");var Ae=E(ze,4,d.joinCount,0);var fd=E(Ae,5,d.bidCount,0);var S=e;rb(fd);if(null!=S){let p=!!S.length;for(let D=0;D<S.length;D++){const X=S[D];p=p&&!(u(X.j)&2)}let v=u(S),K;var gd=v|1;K=(p?gd|8:gd&-9)|4;K!=v&&(S=ib(S,K))}null==S&&(S=void 0);var Be=A(fd,6,S);var Ce=F(Be,7,d.dataVersion);J(ve,11,Ce);f&&J(g,3,f)}}var qa=g;const w={ta:h?.h()??void 0,ea:new Map,Z:new Map,aa:new Map,ba:new Map,ga:new Map,interestGroupName:a??void 0,Ma:R(b,2),Aa:d.joinCount};if(h?.g().C()||h?.g().D()||h?.g().B()){const l=new Map,p=ge();for(const v of p){const K=fe(b,h,v);l.set(N(v,1),K)}w.G=l}if(h){const l=ge()[0];var De=fe(b,h,l);w.modelingSignals=De}const Y=new Map;if(f){for(const l of I(f,Yc,1)){const p=le(O(l,1),O(l,2),O(l,3));Y.set(p,l);be(O(l,2),I(l,Wc,9),w.ea);be(O(l,1),I(l,Wc,10),w.Z);be(O(l,6),I(l,Wc,11),w.aa);be(O(l,7),I(l,Wc,12),w.ba);be(O(l,8),I(l,Wc,13),w.ga)}for(const l of e)w.ea&&ce(l,O(G(l,Ec,2),2),w.ea),w.Z&&ce(l,O(G(l,Ec,2),1),w.Z),w.aa&&ce(l,O(G(l,Ec,2),4),w.aa),w.ba&&ce(l,O(G(l,Ec,2),5),w.ba),w.ga&&ce(l,O(G(l,Ec,2),6),w.ga)}const hd=new Map;if(h)for(const l of I(h,td,2)){const p=le(O(l,1),O(l,2),"");hd.set(p,P(l,3))}const Ib=[];for(const l of c){const p={renderUrl:l.renderUrl,H:O(l.metadata,1),J:O(l.metadata,2),T:O(l.metadata,3),da:O(l.metadata,4),ca:O(l.metadata,5),fa:O(l.metadata,6),na:O(l.metadata,7),Ba:O(l.metadata,8),Ca:O(l.metadata,9),Da:O(l.metadata,10),u:0,M:0},v=le(p.H,p.J,p.T);p.S=hd.get(le(p.H,p.J,""));if(!p.S){if(!h?.g().g()&&!h?.g().h()){qa&&W(qa,p,5,1);continue}else if(!Y.get(v)){qa&&W(qa,p,6,1);continue}p.v=Y.get(v)?.g()??void 0}p.I=Y.get(v)?.h()??void 0;if(p.na&&"0"!==p.na){const K=Y.get(v)?.i()??void 0;var Jb;if(!(Jb=!K)){a:{var Z=p,Ee=K;for(const D of Ee)if(Z.na===O(D,1)&&Z.Ba===O(D,2)&&Z.Ca===O(D,3)&&Z.Da===O(D,4)){Z.I||(Z.I=new Sc);const X=H(D,Sc,5);if(X){for(const sa of I(X,Pc,1))Sb(Z.I,1,Pc,sa);for(const sa of I(X,Rc,2))Sb(Z.I,2,Rc,sa)}var id=!0;break a}id=!1}Jb=!id}if(Jb){qa&&W(qa,p,13,1);continue}}p.oa=Y.get(v)?.B()??void 0;p.sa=Y.get(v)?.C()??void 0;p.Ga=Y.get(v)?.l()??!1;Ib.push(p)}const Kb=h?.P();if(Kb){const l=new Map,p=new Map;for(const D of I(Kb,Pc,1))l.set(R(D,1),D);for(const D of I(Kb,Rc,2))p.set(R(D,1),D);const {Ka:v,Y:K}={Ka:l,Y:p};w.Ea=v;w.Fa=K}w.va=B(b,1,yb)??void 0;const Lb=1!==w.Ma||w.ta?.la()&&!(w.Aa<w.ta?.xa())?1:8;if(1!==Lb&&null!==g)for(const l of Ib)W(g,l,Lb,2);let jd=ie;if(1===Lb){var U=g,kd=h?.h();const l=[],p=new Map;for(const v of Ib){if(void 0!==kd&&kd?.wa()&&(v.renderUrl.includes("/td/adfetch/dv3")||Hd(v.v))){U&&W(U,v,12,3);continue}var aa=v,Ka=w;if(!Td(aa.J,Ka.ea)||!Td(aa.H,Ka.Z)||aa.da&&!Td(aa.da,Ka.aa)||aa.ca&&!Td(aa.ca,Ka.ba)||aa.fa&&!Td(aa.fa,Ka.ga)){U&&W(U,v,3,3);continue}if(v.I){var ld=w;const D=ld.Ea,X=ld.Fa,sa=v.I;if(D&&X&&sa)a:{var Fe=D,Ge=X,md=sa,nd=p;for(const ba of I(md,Pc,1)){const ca=R(ba,1),ta=Ge.get(ca);if(!ta)continue;let da=null;if(M(ba,7)){let La=nd.get(ca),od=!0;const pd=Tb(ba,8);if(void 0===La)La=new Map,nd.set(ca,La);else{const Mb=La.get(pd);if(Mb){var Ma=Mb;break a}null===Mb&&(od=!1)}od&&(da=Od(ba,ta,ca),La.set(pd,da))}else da=Od(ba,ta,ca);if(da){Ma=da;break a}}for(const ba of I(md,Rc,2)){const ca=R(ba,1),ta=Fe.get(ca);if(!ta)continue;const da=Od(ta,ba,ca);if(da){Ma=da;break a}}Ma=null}else Ma=null;const qd=Ma;if(qd){U&&W(U,v,4,3,qd);continue}}if(!Wd(v,w)){U&&W(U,v,7,3);continue}const K=Vd(v,w);1!==K?U&&W(U,v,K,3):l.push(v)}var He={ads:l,X:w};jd=me(He,g,h).ya}if(void 0!==h&&null!==g){if(k){var rd=g,Je=k;E(rd,2,1,0);Dd(Je,rd)}if(m){var sd=g,Ke=m;E(sd,2,2,0);Dd(Ke,sd)}}return jd}function W(a,b,c,d,e){a=Sb(a,10,Uc);d=E(a,3,d,0);var f=new Tc;f=E(f,1,b.renderUrl,"");f=E(f,2,b.H,"");f=E(f,3,b.J,"");f=E(f,4,b.T,"");f=F(f,12,b.u);f=F(f,13,b.M);var h=b.Ha??!1;f=E(f,16,null==h?h:!!h,!1);void 0!==b.da&&E(f,5,b.da,"");void 0!==b.ca&&E(f,6,b.ca,"");void 0!==b.fa&&E(f,7,b.fa,"");void 0!==b.v&&J(f,8,b.v);void 0!==b.ia&&F(f,9,b.ia);void 0!==b.W&&F(f,10,b.W);void 0!==b.S&&F(f,11,b.S);void 0!==b.I&&J(f,14,b.I);for(const g of b.oa??[])b=f,h=g,rb(b),Cb(b,15,2,!1).push(h);J(d,1,f);void 0!==e&&E(a,5,e,0);Object.values(Nd).includes(c)&&E(a,2,c,0)}function me(a,b,c){var d=[],e=[];for(var f of a.ads)if(null!=f.S)f.u=f.S,f.Ha=!0,d.push(f);else{c?.g().g()?(Hd(f.v)?f.W=$d({R:H(c,ad,1),v:f.v,G:a.X.G,U:c.g().B()}):(f.ia=Xd({R:H(c,ad,1),v:f.v,G:a.X.G,U:c.g().C()}),f.W=Zd({R:H(c,ad,1),v:f.v,G:a.X.G,U:c.g().D()})),f.u=Md(f,P(c.g(),12),f.v),M(c.g(),13)&&!f.u&&(f.u=f.v?.h()??0)):c?.g().h()&&(f.u=f.v?.h()??0);if(c?.g().l())if(f.H!==c?.i()?.l()||0<(c?.i()?.g()??"").length&&0<(c?.i()?.h()??"").length&&(f.J!==c?.i()?.g()||a.X.interestGroupName!==c?.i()?.h()))f.u=0;else if(c?.i()?.i()){var h=c?.i()?.B()??0;f.u=0===h?1:h}e.push(f)}e={renderUrl:"",H:"",J:"",T:"",u:0,M:0};c?.g().l()&&c?.i()?.i()?(c=a.ads.reduce((g,k)=>g.u<k.u?k:g,e),c.M=c.u):(d=a.ads.reduce((g,k)=>!Hd(k.v)&&g.u<k.u?k:g,e),h=a.ads.reduce((g,k)=>Hd(k.v)&&g.u<k.u?k:g,e),e=Kd(c,d?.u),e.o=Fd(e.o,c?.h()?.L()?.D()),f=Id(c,h?.u),f.o=Fd(f.o,c?.h()?.i()?.D()),e.o>f.o?(c=d,c.M=e.o):(c=h,c.M=f.o));if(b)for(const g of a.ads)W(b,g,le(g.H,g.J,g.T)===le(c.H,c.J,c.T)?1:9,4);return{ya:{ad:{},bid:c.M/1E6,bidCurrency:"USD",render:c.renderUrl,allowComponentAuction:!0,modelingSignals:a.X.modelingSignals,adCost:42},debugInfo:void 0}}function le(a,b,c){return a.concat("+",b,"+",c)};const ne=globalThis;function oe(a,b){var c={id:"fledge_auction_winner"};c.winner_qid=b?.l()||-1;a=a.renderUrl.split("?")[1]?.split("&")??[];for(const d of a)if(a=d.split("="),"cr_id"===a[0]){c.winner_cid=a[1];break}c=Object.entries(c).map(([d,e])=>`${encodeURIComponent(d)}=${encodeURIComponent(e)}`).join("&");ne.sendReportTo(`${"https://pagead2.googlesyndication.com/pagead/gen_204"}?${c}`)};const pe=globalThis;function qe(a){let b=0;a=Rb(G(G(a,Ad,1),zd,3),yd,1);if(!a)return 0;for(const c of a)null!=L(z(c,2),0)&&b<L(z(c,2),0)&&(b=L(z(c,2),0));return b}function re(a,b,c,d,e,f){const h=c?Array.isArray(c)?new Bd(c):c:void 0;var g={};g.haveSellerSignals=h?1:0;g.haveBuyerSignals=e?1:0;g.winner_qid=(h||e)?.l()||-1;g.xfpQid=h?.B()||-1;g.is_plog=h?.C()?1:0;g.ecrs=h?.g()||"";g.cf=h?.h()?.g()||0;g.pf=h?qe(h):0;g.pubp=e?.B()||0;h?.D()||(g.turtlexTest=1);g.tdeid=B(a,1,ub).join(",");g.bid=b.winningBidCpmUsdMicros;g.hsobid=b.highestScoringOtherBidCpmUsdMicros;(a=e?.la().C())&&"0"!==a&&(g.ddid=a);d&&(g.desirability=d.desirability,g.igown=d.interestGroupOwner,g.rurl=d.renderUrl,g.topWindowHostname=d.topWindowHostname,g.bsig=JSON.stringify(d),g.sdv=d.dataVersion??-1);f&&(g.igown=f.interestGroupOwner,g.wign=f.interestGroupName,g.rurl=f.renderUrl,g.topWindowHostname=f.topWindowHostname,g.bdv=f.dataVersion??-1,g.modelingSignals=f.modelingSignals??-1,g.joinCount=f.joinCount??-1,g.recency=f.recency??-1,g.adCost=f.adCost??-1);g=`${"https://googleads.g.doubleclick.net/td/auctionwinner"}?${Object.entries(g).map(([k,m])=>`${encodeURIComponent(k)}=${encodeURIComponent(m)}`).join("&")}`;e?.C()?se(g,b,c,d,e,f):(pe.sendReportTo(g),d&&!["https://googleads.g.doubleclick.net","https://td.doubleclick.net"].includes(d.interestGroupOwner)&&Ie(b,c,d))}function Le(a,b,c,d,e){const f=b?Array.isArray(b)?Cd(JSON.stringify(b)):b:void 0;b={};b.bid=a.winningBidCpmUsdMicros;b.cid=f?.i()||"";b.ecrs=f?.g()||"";b.winner_qid=(d||f)?.l()||-1;c&&(b.rurl=c.renderUrl??"",b.igown=c.interestGroupOwner);e&&(b.wbid=1E6*e.bid,b.wign=e.interestGroupName??"");d&&((a=G(d,ad,1))&&(b.bqs=JSON.stringify(a.toJSON())),(a=G(d,dd,6))&&(b.gfpa=JSON.stringify(a.toJSON())),(a=d.g())&&(b.qf=JSON.stringify(a.toJSON())),b.mafprcu=d.D()||0,b.pubp=d.B()||0);return Object.entries(b).map(([h,g])=>`${encodeURIComponent(h)}=${encodeURIComponent(g)}`).join("&")}function Ie(a,b,c){a=`${"https://googleads.g.doubleclick.net/td/adclick"}?${Le(a,b,c)}`;pe.registerAdBeacon?.({click:a})}function se(a,b,c,d,e,f){b=Le(b,c,d,e,f);c=`${"https://googleads.g.doubleclick.net/td/adclick"}?${b}`;d=`${"https://www.googleadservices.com/td/adview"}?${b}`;e=`${"https://www.googleadservices.com/td/adclick"}?${b}`+"&navigation=1";f&&f.renderUrl.includes("/td/adfetch/dv3")&&(e=`${"https://ad.doubleclick.net/td/adclick"}?${b}`+"&navigation=1",d=`${"https://ad.doubleclick.net/td/adview"}?${b}`);pe.registerAdBeacon?.({click:c,impression:d,interaction:`${"https://googleads.g.doubleclick.net/td/adinteraction"}?${b}`,auctionwinner:a,"reserved.top_navigation":e,["active-view-viewable"]:`${"https://googleads.g.doubleclick.net/td/activeview"}?acvw=td_r%3Dviewable&${b}`,["active-view-time-on-screen"]:`${"https://googleads.g.doubleclick.net/td/activeview"}?acvw=td_r%3Dtos&${b}`,["active-view-unmeasurable"]:`${"https://googleads.g.doubleclick.net/td/activeview"}?acvw=td_r%3Dunmeasurable&${b}`,["active-view-begin-to-render"]:`${"https://googleads.g.doubleclick.net/td/activeview"}?acvw=td_r%3Db2r&${b}`,["active-view-error"]:"https://pagead2.googlesyndication.com/pagead/gen_204?id=av-js&type=error&bin=7&td=1"})};var Me=yc(class extends T{}),Hb=[3,4];const Ne=globalThis;var Gb,Oe=stc;tc(Oe,a=>"string"===typeof a);Gb=Me(Oe);var Pe,Qe=3===Nb();const Re=uc();if(!Qe)throw Error(Re&&Re()||String(Qe));var Se;Se=3===Nb();Pe=H(Gb,he,Se?3:-1);Ne.generateBid=(a,b,c,d,e)=>je(a,c,d,e);Ne.reportWin=function(a){return(b,c,d,e)=>{b=c?new vd(vc(c)):void 0;d=["https://securepubads.g.doubleclick.net","https://pubads.g.doubleclick.net"].includes(e.seller)?d:void 0;c={winningBidCpmUsdMicros:1E6*e.bid,highestScoringOtherBidCpmUsdMicros:1E6*e.highestScoringOtherBid};b?.C()&&oe(e,b);re(a,c,d?.sellerSignalsJspb,d?.sellerReportingBrowserSignals,b,e)}}(Pe);}).call(this,"[null,null,[]]");
)";
constexpr std::string_view kHandlerNameGoogleAdManagerGenerateBid =
    "generateBid";

}  // namespace google::scp::roma::benchmark
