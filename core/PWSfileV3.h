/*
* Copyright (c) 2003-2016 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
#ifndef __PWSFILEV3_H
#define __PWSFILEV3_H

// PWSfileV3.h
// Abstract the gory details of reading and writing an encrypted database
//-----------------------------------------------------------------------------

#include "PWSfile.h"
#include "TwoFish.h"
#include "sha256.h"
#include "hmac.h"
#include "UTF8Conv.h"

class PWSfileV3 : public PWSfile
{
public:

  static task<int> CheckPasskey(const StringX &filename,
                          const StringX &passkey,
                          IRandomAccessStream^ a_fd = nullptr,
                          unsigned char *aPtag = NULL, uint32 *nIter = NULL);
  static task<bool> IsV3x(const StringX &filename, VERSION &v);

  PWSfileV3(const StringX &filename, RWmode mode, VERSION version);
  ~PWSfileV3();

  virtual task<int> Open(const StringX &passkey);
  virtual task<int> Close();

  virtual task<int> WriteRecord(const CItemData &item);
  virtual task<int> ReadRecord(CItemData &item);

  virtual uint32 GetNHashIters() const {return m_nHashIters;}
  virtual void SetNHashIters(uint32 N) {m_nHashIters = N;}

 private:
  enum {PWSaltLength = 32}; // per format spec
  uint32 m_nHashIters;
  unsigned char m_ipthing[TwoFish::BLOCKSIZE]; // for CBC
  unsigned char m_key[32];
  HMAC<SHA256, SHA256::HASHLEN, SHA256::BLOCKSIZE> m_hmac;
  CUTF8Conv m_utf8conv;
  virtual task<size_t> WriteCBC(unsigned char type, const StringX &data);
  virtual task<size_t> WriteCBC(unsigned char type, const unsigned char *data,
                          size_t length);

  virtual task<size_t> ReadCBC(unsigned char &type, unsigned char* &data,
                         size_t &length);
  task<int> WriteHeader();
  task<int> ReadHeader();

  static int SanityCheck(FILE *stream); // Check for TAG and EOF marker
  static void StretchKey(const unsigned char *salt, unsigned long saltLen,
                         const StringX &passkey,
                         uint32 N, unsigned char *Ptag);
};
#endif /* __PWSFILEV3_H */
