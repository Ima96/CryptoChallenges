/***********************************************************************************************************************
 * @file    main.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Solution to Challenge 19 and 20 of Cryptopals CryptoChallenges. As the challenge 19 has no sense to be 
 *          done programatically alone, and the first the idea is to use the similar algorithm to break repeating key 
 *          XOR cipher in the next challenge, challenge 20, they are fused in only one and challenge 20 is done.
 * 
 * @version 0.1
 * @date    21/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "encodings.h"
#include "misc.h"

static uint8_t * pu8_au8_plainb64_pool_ch19[] = 
{
   "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
   "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
   "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
   "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
   "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
   "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
   "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
   "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
   "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
   "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
   "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
   "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
   "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
   "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
   "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
   "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
   "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
   "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
   "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
   "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
   "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
   "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
   "U2hlIHJvZGUgdG8gaGFycmllcnM/",
   "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
   "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
   "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
   "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
   "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
   "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
   "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
   "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
   "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
   "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
   "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
   "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
   "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
   "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
   "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
   "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
   "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
};

static uint8_t * pu8_au8_plainb64_pool_ch20[] =
{
   "SSdtIHJhdGVkICJSIi4uLnRoaXMgaXMgYSB3YXJuaW5nLCB5YSBiZXR0ZXIgdm9pZCAvIFBvZXRzIGFyZSBwYXJhbm9pZCwgREoncyBELXN0cm95ZWQ=",
   "Q3V6IEkgY2FtZSBiYWNrIHRvIGF0dGFjayBvdGhlcnMgaW4gc3BpdGUtIC8gU3RyaWtlIGxpa2UgbGlnaHRuaW4nLCBJdCdzIHF1aXRlIGZyaWdodGVuaW4nIQ==",
   "QnV0IGRvbid0IGJlIGFmcmFpZCBpbiB0aGUgZGFyaywgaW4gYSBwYXJrIC8gTm90IGEgc2NyZWFtIG9yIGEgY3J5LCBvciBhIGJhcmssIG1vcmUgbGlrZSBhIHNwYXJrOw==",
   "WWEgdHJlbWJsZSBsaWtlIGEgYWxjb2hvbGljLCBtdXNjbGVzIHRpZ2h0ZW4gdXAgLyBXaGF0J3MgdGhhdCwgbGlnaHRlbiB1cCEgWW91IHNlZSBhIHNpZ2h0IGJ1dA==",
   "U3VkZGVubHkgeW91IGZlZWwgbGlrZSB5b3VyIGluIGEgaG9ycm9yIGZsaWNrIC8gWW91IGdyYWIgeW91ciBoZWFydCB0aGVuIHdpc2ggZm9yIHRvbW9ycm93IHF1aWNrIQ==",
   "TXVzaWMncyB0aGUgY2x1ZSwgd2hlbiBJIGNvbWUgeW91ciB3YXJuZWQgLyBBcG9jYWx5cHNlIE5vdywgd2hlbiBJJ20gZG9uZSwgeWEgZ29uZSE=",
   "SGF2ZW4ndCB5b3UgZXZlciBoZWFyZCBvZiBhIE1DLW11cmRlcmVyPyAvIFRoaXMgaXMgdGhlIGRlYXRoIHBlbmFsdHksYW5kIEknbSBzZXJ2aW4nIGE=",
   "RGVhdGggd2lzaCwgc28gY29tZSBvbiwgc3RlcCB0byB0aGlzIC8gSHlzdGVyaWNhbCBpZGVhIGZvciBhIGx5cmljYWwgcHJvZmVzc2lvbmlzdCE=",
   "RnJpZGF5IHRoZSB0aGlydGVlbnRoLCB3YWxraW5nIGRvd24gRWxtIFN0cmVldCAvIFlvdSBjb21lIGluIG15IHJlYWxtIHlhIGdldCBiZWF0IQ==",
   "VGhpcyBpcyBvZmYgbGltaXRzLCBzbyB5b3VyIHZpc2lvbnMgYXJlIGJsdXJyeSAvIEFsbCB5YSBzZWUgaXMgdGhlIG1ldGVycyBhdCBhIHZvbHVtZQ==",
   "VGVycm9yIGluIHRoZSBzdHlsZXMsIG5ldmVyIGVycm9yLWZpbGVzIC8gSW5kZWVkIEknbSBrbm93bi15b3VyIGV4aWxlZCE=",
   "Rm9yIHRob3NlIHRoYXQgb3Bwb3NlIHRvIGJlIGxldmVsIG9yIG5leHQgdG8gdGhpcyAvIEkgYWluJ3QgYSBkZXZpbCBhbmQgdGhpcyBhaW4ndCB0aGUgRXhvcmNpc3Qh",
   "V29yc2UgdGhhbiBhIG5pZ2h0bWFyZSwgeW91IGRvbid0IGhhdmUgdG8gc2xlZXAgYSB3aW5rIC8gVGhlIHBhaW4ncyBhIG1pZ3JhaW5lIGV2ZXJ5IHRpbWUgeWEgdGhpbms=",
   "Rmxhc2hiYWNrcyBpbnRlcmZlcmUsIHlhIHN0YXJ0IHRvIGhlYXI6IC8gVGhlIFItQS1LLUktTSBpbiB5b3VyIGVhcjs=",
   "VGhlbiB0aGUgYmVhdCBpcyBoeXN0ZXJpY2FsIC8gVGhhdCBtYWtlcyBFcmljIGdvIGdldCBhIGF4IGFuZCBjaG9wcyB0aGUgd2Fjaw==",
   "U29vbiB0aGUgbHlyaWNhbCBmb3JtYXQgaXMgc3VwZXJpb3IgLyBGYWNlcyBvZiBkZWF0aCByZW1haW4=",
   "TUMncyBkZWNheWluZywgY3V6IHRoZXkgbmV2ZXIgc3RheWVkIC8gVGhlIHNjZW5lIG9mIGEgY3JpbWUgZXZlcnkgbmlnaHQgYXQgdGhlIHNob3c=",
   "VGhlIGZpZW5kIG9mIGEgcmh5bWUgb24gdGhlIG1pYyB0aGF0IHlvdSBrbm93IC8gSXQncyBvbmx5IG9uZSBjYXBhYmxlLCBicmVha3MtdGhlIHVuYnJlYWthYmxl",
   "TWVsb2RpZXMtdW5tYWthYmxlLCBwYXR0ZXJuLXVuZXNjYXBhYmxlIC8gQSBob3JuIGlmIHdhbnQgdGhlIHN0eWxlIEkgcG9zc2Vz",
   "SSBibGVzcyB0aGUgY2hpbGQsIHRoZSBlYXJ0aCwgdGhlIGdvZHMgYW5kIGJvbWIgdGhlIHJlc3QgLyBGb3IgdGhvc2UgdGhhdCBlbnZ5IGEgTUMgaXQgY2FuIGJl",
   "SGF6YXJkb3VzIHRvIHlvdXIgaGVhbHRoIHNvIGJlIGZyaWVuZGx5IC8gQSBtYXR0ZXIgb2YgbGlmZSBhbmQgZGVhdGgsIGp1c3QgbGlrZSBhIGV0Y2gtYS1za2V0Y2g=",
   "U2hha2UgJ3RpbGwgeW91ciBjbGVhciwgbWFrZSBpdCBkaXNhcHBlYXIsIG1ha2UgdGhlIG5leHQgLyBBZnRlciB0aGUgY2VyZW1vbnksIGxldCB0aGUgcmh5bWUgcmVzdCBpbiBwZWFjZQ==",
   "SWYgbm90LCBteSBzb3VsJ2xsIHJlbGVhc2UhIC8gVGhlIHNjZW5lIGlzIHJlY3JlYXRlZCwgcmVpbmNhcm5hdGVkLCB1cGRhdGVkLCBJJ20gZ2xhZCB5b3UgbWFkZSBpdA==",
   "Q3V6IHlvdXIgYWJvdXQgdG8gc2VlIGEgZGlzYXN0cm91cyBzaWdodCAvIEEgcGVyZm9ybWFuY2UgbmV2ZXIgYWdhaW4gcGVyZm9ybWVkIG9uIGEgbWljOg==",
   "THlyaWNzIG9mIGZ1cnkhIEEgZmVhcmlmaWVkIGZyZWVzdHlsZSEgLyBUaGUgIlIiIGlzIGluIHRoZSBob3VzZS10b28gbXVjaCB0ZW5zaW9uIQ==",
   "TWFrZSBzdXJlIHRoZSBzeXN0ZW0ncyBsb3VkIHdoZW4gSSBtZW50aW9uIC8gUGhyYXNlcyB0aGF0J3MgZmVhcnNvbWU=",
   "WW91IHdhbnQgdG8gaGVhciBzb21lIHNvdW5kcyB0aGF0IG5vdCBvbmx5IHBvdW5kcyBidXQgcGxlYXNlIHlvdXIgZWFyZHJ1bXM7IC8gSSBzaXQgYmFjayBhbmQgb2JzZXJ2ZSB0aGUgd2hvbGUgc2NlbmVyeQ==",
   "VGhlbiBub25jaGFsYW50bHkgdGVsbCB5b3Ugd2hhdCBpdCBtZWFuIHRvIG1lIC8gU3RyaWN0bHkgYnVzaW5lc3MgSSdtIHF1aWNrbHkgaW4gdGhpcyBtb29k",
   "QW5kIEkgZG9uJ3QgY2FyZSBpZiB0aGUgd2hvbGUgY3Jvd2QncyBhIHdpdG5lc3MhIC8gSSdtIGEgdGVhciB5b3UgYXBhcnQgYnV0IEknbSBhIHNwYXJlIHlvdSBhIGhlYXJ0",
   "UHJvZ3JhbSBpbnRvIHRoZSBzcGVlZCBvZiB0aGUgcmh5bWUsIHByZXBhcmUgdG8gc3RhcnQgLyBSaHl0aG0ncyBvdXQgb2YgdGhlIHJhZGl1cywgaW5zYW5lIGFzIHRoZSBjcmF6aWVzdA==",
   "TXVzaWNhbCBtYWRuZXNzIE1DIGV2ZXIgbWFkZSwgc2VlIGl0J3MgLyBOb3cgYW4gZW1lcmdlbmN5LCBvcGVuLWhlYXJ0IHN1cmdlcnk=",
   "T3BlbiB5b3VyIG1pbmQsIHlvdSB3aWxsIGZpbmQgZXZlcnkgd29yZCdsbCBiZSAvIEZ1cmllciB0aGFuIGV2ZXIsIEkgcmVtYWluIHRoZSBmdXJ0dXJl",
   "QmF0dGxlJ3MgdGVtcHRpbmcuLi53aGF0ZXZlciBzdWl0cyB5YSEgLyBGb3Igd29yZHMgdGhlIHNlbnRlbmNlLCB0aGVyZSdzIG5vIHJlc2VtYmxhbmNl",
   "WW91IHRoaW5rIHlvdSdyZSBydWZmZXIsIHRoZW4gc3VmZmVyIHRoZSBjb25zZXF1ZW5jZXMhIC8gSSdtIG5ldmVyIGR5aW5nLXRlcnJpZnlpbmcgcmVzdWx0cw==",
   "SSB3YWtlIHlhIHdpdGggaHVuZHJlZHMgb2YgdGhvdXNhbmRzIG9mIHZvbHRzIC8gTWljLXRvLW1vdXRoIHJlc3VzY2l0YXRpb24sIHJoeXRobSB3aXRoIHJhZGlhdGlvbg==",
   "Tm92b2NhaW4gZWFzZSB0aGUgcGFpbiBpdCBtaWdodCBzYXZlIGhpbSAvIElmIG5vdCwgRXJpYyBCLidzIHRoZSBqdWRnZSwgdGhlIGNyb3dkJ3MgdGhlIGp1cnk=",
   "WW8gUmFraW0sIHdoYXQncyB1cD8gLyBZbywgSSdtIGRvaW5nIHRoZSBrbm93bGVkZ2UsIEUuLCBtYW4gSSdtIHRyeWluZyB0byBnZXQgcGFpZCBpbiBmdWxs",
   "V2VsbCwgY2hlY2sgdGhpcyBvdXQsIHNpbmNlIE5vcmJ5IFdhbHRlcnMgaXMgb3VyIGFnZW5jeSwgcmlnaHQ/IC8gVHJ1ZQ==",
   "S2FyYSBMZXdpcyBpcyBvdXIgYWdlbnQsIHdvcmQgdXAgLyBaYWtpYSBhbmQgNHRoIGFuZCBCcm9hZHdheSBpcyBvdXIgcmVjb3JkIGNvbXBhbnksIGluZGVlZA==",
   "T2theSwgc28gd2hvIHdlIHJvbGxpbicgd2l0aCB0aGVuPyBXZSByb2xsaW4nIHdpdGggUnVzaCAvIE9mIFJ1c2h0b3duIE1hbmFnZW1lbnQ=",
   "Q2hlY2sgdGhpcyBvdXQsIHNpbmNlIHdlIHRhbGtpbmcgb3ZlciAvIFRoaXMgZGVmIGJlYXQgcmlnaHQgaGVyZSB0aGF0IEkgcHV0IHRvZ2V0aGVy",
   "SSB3YW5uYSBoZWFyIHNvbWUgb2YgdGhlbSBkZWYgcmh5bWVzLCB5b3Uga25vdyB3aGF0IEknbSBzYXlpbic/IC8gQW5kIHRvZ2V0aGVyLCB3ZSBjYW4gZ2V0IHBhaWQgaW4gZnVsbA==",
   "VGhpbmtpbicgb2YgYSBtYXN0ZXIgcGxhbiAvICdDdXogYWluJ3QgbnV0aGluJyBidXQgc3dlYXQgaW5zaWRlIG15IGhhbmQ=",
   "U28gSSBkaWcgaW50byBteSBwb2NrZXQsIGFsbCBteSBtb25leSBpcyBzcGVudCAvIFNvIEkgZGlnIGRlZXBlciBidXQgc3RpbGwgY29taW4nIHVwIHdpdGggbGludA==",
   "U28gSSBzdGFydCBteSBtaXNzaW9uLCBsZWF2ZSBteSByZXNpZGVuY2UgLyBUaGlua2luJyBob3cgY291bGQgSSBnZXQgc29tZSBkZWFkIHByZXNpZGVudHM=",
   "SSBuZWVkIG1vbmV5LCBJIHVzZWQgdG8gYmUgYSBzdGljay11cCBraWQgLyBTbyBJIHRoaW5rIG9mIGFsbCB0aGUgZGV2aW91cyB0aGluZ3MgSSBkaWQ=",
   "SSB1c2VkIHRvIHJvbGwgdXAsIHRoaXMgaXMgYSBob2xkIHVwLCBhaW4ndCBudXRoaW4nIGZ1bm55IC8gU3RvcCBzbWlsaW5nLCBiZSBzdGlsbCwgZG9uJ3QgbnV0aGluJyBtb3ZlIGJ1dCB0aGUgbW9uZXk=",
   "QnV0IG5vdyBJIGxlYXJuZWQgdG8gZWFybiAnY3V6IEknbSByaWdodGVvdXMgLyBJIGZlZWwgZ3JlYXQsIHNvIG1heWJlIEkgbWlnaHQganVzdA==",
   "U2VhcmNoIGZvciBhIG5pbmUgdG8gZml2ZSwgaWYgSSBzdHJpdmUgLyBUaGVuIG1heWJlIEknbGwgc3RheSBhbGl2ZQ==",
   "U28gSSB3YWxrIHVwIHRoZSBzdHJlZXQgd2hpc3RsaW4nIHRoaXMgLyBGZWVsaW4nIG91dCBvZiBwbGFjZSAnY3V6LCBtYW4sIGRvIEkgbWlzcw==",
   "QSBwZW4gYW5kIGEgcGFwZXIsIGEgc3RlcmVvLCBhIHRhcGUgb2YgLyBNZSBhbmQgRXJpYyBCLCBhbmQgYSBuaWNlIGJpZyBwbGF0ZSBvZg==",
   "RmlzaCwgd2hpY2ggaXMgbXkgZmF2b3JpdGUgZGlzaCAvIEJ1dCB3aXRob3V0IG5vIG1vbmV5IGl0J3Mgc3RpbGwgYSB3aXNo",
   "J0N1eiBJIGRvbid0IGxpa2UgdG8gZHJlYW0gYWJvdXQgZ2V0dGluJyBwYWlkIC8gU28gSSBkaWcgaW50byB0aGUgYm9va3Mgb2YgdGhlIHJoeW1lcyB0aGF0IEkgbWFkZQ==",
   "U28gbm93IHRvIHRlc3QgdG8gc2VlIGlmIEkgZ290IHB1bGwgLyBIaXQgdGhlIHN0dWRpbywgJ2N1eiBJJ20gcGFpZCBpbiBmdWxs",
   "UmFraW0sIGNoZWNrIHRoaXMgb3V0LCB5byAvIFlvdSBnbyB0byB5b3VyIGdpcmwgaG91c2UgYW5kIEknbGwgZ28gdG8gbWluZQ==",
   "J0NhdXNlIG15IGdpcmwgaXMgZGVmaW5pdGVseSBtYWQgLyAnQ2F1c2UgaXQgdG9vayB1cyB0b28gbG9uZyB0byBkbyB0aGlzIGFsYnVt",
   "WW8sIEkgaGVhciB3aGF0IHlvdSdyZSBzYXlpbmcgLyBTbyBsZXQncyBqdXN0IHB1bXAgdGhlIG11c2ljIHVw",
   "QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbGk=",
   "VHVybiBkb3duIHRoZSBiYXNzIGRvd24gLyBBbmQgbGV0IHRoZSBiZWF0IGp1c3Qga2VlcCBvbiByb2NraW4n",
   "QW5kIHdlIG91dHRhIGhlcmUgLyBZbywgd2hhdCBoYXBwZW5lZCB0byBwZWFjZT8gLyBQZWFjZQ=="
};

void safe_2d_free(void ** pp_buffer, uint64_t u64_rows)
{
   for (uint64_t u64_idx = 0; u64_idx < u64_rows; u64_idx++)
      ss_free(pp_buffer[u64_idx], strlen(pp_buffer[u64_idx]));

   if (pp_buffer)
      free(pp_buffer);
}

int main(int argc, char * argv[])
{
   printf("=========== CryptoPals: Challenge 19 & 20 ===========\n");

   int32_t i32_retval = EXIT_FAILURE;
   uint8_t u8_ch_option = 0;

   if (argc != 2)
   {
      printf("Usage: ./ch19_20_fixed_nonce_ctr_subs_break [19 OR 20]\n"
               "  - 19: Execute with input from Challenge 19\n"
               "  - 20: Execute with input from Challenge 20\n");
      return i32_retval;
   }

   if (0 != strcmp(argv[1], "19") && 0 != strcmp(argv[1], "20"))
   {
      printf("Usage: ./ch19_20_fixed_nonce_ctr_subs_break [19 OR 20]\n"
            "  - 19: Execute with input from Challenge 19\n"
            "  - 20: Execute with input from Challenge 20\n");
      return i32_retval;
   }
   
   u8_ch_option = (uint8_t) atoi(argv[1]);

   // Create the original CTR configuration
   struct SAES128CTR_config s_ctr_config;
   s_ctr_config.m_u64_nonce = 0;

   i32_retval = GenRndAES128Key(s_ctr_config.m_au8_key);

   // Ch19
   uint8_t u8_pool_rows = 0;
   if (u8_ch_option == 19)
      u8_pool_rows = sizeof(pu8_au8_plainb64_pool_ch19)/sizeof(pu8_au8_plainb64_pool_ch19[0]);
   else // Ch20
      u8_pool_rows = sizeof(pu8_au8_plainb64_pool_ch20)/sizeof(pu8_au8_plainb64_pool_ch20[0]);

   struct OArray * po_ciphertext_pool = calloc(u8_pool_rows, sizeof(struct OArray));
   for (uint8_t u8_idx = 0; u8_idx < u8_pool_rows; u8_idx++)
   {
      uint16_t u16_curr_plaintext_len = 0;
      uint8_t * pu8_curr_plaintxt_dec = NULL;
      // Ch19
      if (u8_ch_option == 19)
      {
         uint16_t u16_curr_plainb64_len = strlen(pu8_au8_plainb64_pool_ch19[u8_idx]);
         pu8_curr_plaintxt_dec = DecodeBase64(pu8_au8_plainb64_pool_ch19[u8_idx], 
                                                         u16_curr_plainb64_len, 
                                                         &u16_curr_plaintext_len);
      }
      else // Ch20
      {
         uint16_t u16_curr_plainb64_len = strlen(pu8_au8_plainb64_pool_ch20[u8_idx]);
         pu8_curr_plaintxt_dec = DecodeBase64(pu8_au8_plainb64_pool_ch20[u8_idx], 
                                                         u16_curr_plainb64_len, 
                                                         &u16_curr_plaintext_len);
      }
      
      

      i32_retval = AES128CTR_function(pu8_curr_plaintxt_dec, 
                                       u16_curr_plaintext_len, 
                                       s_ctr_config, 
                                       &(po_ciphertext_pool[u8_idx].m_pu8_data));
      po_ciphertext_pool[u8_idx].m_u32_length = u16_curr_plaintext_len;

      ss_free(pu8_curr_plaintxt_dec, u16_curr_plaintext_len);
   }

   uint8_t ** ppu8_guessed_plaintext_pool = NULL;
   i32_retval = AES128CTR_break_fixed_nonce(po_ciphertext_pool, u8_pool_rows, &ppu8_guessed_plaintext_pool);

   if (i32_retval == CRYPTO_OK)
   {
      printf("[INFO] Guessed plaintexts are:\n");
      for (uint8_t u8_idx = 0; u8_idx < u8_pool_rows; u8_idx++)
      {
         printf("  [INFO] Plaintxt #%d: %s\n", u8_idx, ppu8_guessed_plaintext_pool[u8_idx]);
      }
   }
   

   /* Clean up */
   safe_2d_free((void **)ppu8_guessed_plaintext_pool, u8_pool_rows);
   for (uint8_t u8_idx = 0; u8_idx < u8_pool_rows; u8_idx++)
   {
      ss_free((po_ciphertext_pool[u8_idx]).m_pu8_data, (po_ciphertext_pool[u8_idx]).m_u32_length);
   }
   ss_free(po_ciphertext_pool, u8_pool_rows);

   return i32_retval;
}