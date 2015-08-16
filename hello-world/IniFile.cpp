// C Includes
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
// C++ Includes
#include <iostream>
#include <fstream>

using namespace std;

// Local Includes
#include "IniFile.h"

#if defined(WIN32)
#define iniEOL endl
#else
#define iniEOL '\r' << endl
#endif

CIniFile::CIniFile( string const iniPath)
{
  SetPath( iniPath);
  caseInsensitive = true;
}

bool CIniFile::ReadFile()
{
  // Normally you would use ifstream, but the SGI CC compiler has
  // a few bugs with ifstream. So ... fstream used.
  fstream f;
  string   line;
  string   secname, key, value;
  string::size_type pLeft, pRight;

  f.open( path.c_str(), ios::in);
  if ( f.fail())
    return false;
  
  while( getline( f, line)) {
	  if(line.length() < 1){
		  continue;
	  }
    // To be compatible with Win32, check for existence of '\r'.
    // Win32 files have the '\r' and Unix files don't at the end of a line.
    // Note that the '\r' will be written to INI files from
    // Unix so that the created INI file can be read under Win32
    // without change.
    if ( line[line.length() - 1] == '\r')
      line = line.substr( 0, line.length() - 1);
    
    if ( line.length()) {
      // Check that the user hasn't openned a binary file by checking the first
      // character of each line!
      if ( !isprint( line[0])) {
	printf( "Failing on char %d\n", line[0]);
	f.close();
	return false;
      }
      if (( pLeft = line.find_first_of(";#[=")) != string::npos) {
	switch ( line[pLeft]) {
	case '[':
	  if ((pRight = line.find_last_of("]")) != string::npos &&
	      pRight > pLeft) {
	    secname = line.substr( pLeft + 1, pRight - pLeft - 1);
	    AddSectionName( secname);
	  }
	  break;
	  
	case '=':
	  key = line.substr( 0, pLeft);
	  value = line.substr( pLeft + 1);
	  SetValue( secname, key, value);
	  break;
	  
	case ';':
	case '#':
	  if ( !m_secnames.size())
	    AddHeaderComment( line.substr( pLeft + 1));
	  else
	    AddSectionComment( secname, line.substr( pLeft + 1));
	  break;
	}
      }
    }
  }

  f.close();
  if ( m_secnames.size())
    return true;
  return false;
}

long CIniFile::FindSection( string const secname) const
{
  for ( unsigned sectionID = 0; sectionID < m_secnames.size(); ++sectionID)
    if ( CheckCase( m_secnames[sectionID]) == CheckCase( secname))
      return long(sectionID);
  return noID;
}

long CIniFile::FindKey( unsigned const sectionID, string const key) const
{
  if ( !m_sections.size() || sectionID >= m_sections.size())
    return noID;

  for ( unsigned keyId = 0; keyId < m_sections[sectionID].keys.size(); ++keyId)
    if ( CheckCase( m_sections[sectionID].keys[keyId]) == CheckCase( key))
      return long(keyId);
  return noID;
}

unsigned CIniFile::AddSectionName( string const secname)
{
  m_secnames.resize( m_secnames.size() + 1, secname);
  m_sections.resize( m_sections.size() + 1);
  return m_secnames.size() - 1;
}

string CIniFile::GetSectionName( unsigned const sectionID) const
{
  if ( sectionID < m_secnames.size())
    return m_secnames[sectionID];
  else
    return "";
}

unsigned CIniFile::GetNumKeys( unsigned const sectionID)
{
  if ( sectionID < m_sections.size())
    return m_sections[sectionID].keys.size();
  return 0;
}

unsigned CIniFile::GetNumKeys( string const secname)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return 0;
  return m_sections[sectionID].keys.size();
}

vector<string>* CIniFile::GetKeys(string const secname)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID){
    return NULL;
  }
  
  return &m_sections[sectionID].keys;
}

string CIniFile::GetValue( unsigned const sectionID, unsigned const keyId, string const defValue) const
{
  if ( sectionID < m_sections.size() && keyId < m_sections[sectionID].keys.size())
    return m_sections[sectionID].values[keyId];
  return defValue;
}

string CIniFile::GetValue( string const secname, string const key, string const defValue) const
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return defValue;

  long keyId = FindKey( unsigned(sectionID), key);
  if ( keyId == noID)
    return defValue;

  return m_sections[sectionID].values[keyId];
}

int CIniFile::GetValueI(string const secname, string const key, int const defValue) const
{
  char svalue[MAX_VALUE];

  sprintf( svalue, "%d", defValue);
  return atoi( GetValue( secname, key, svalue).c_str()); 
}

long long CIniFile::GetValueLL(string const secname, string const key, long long const defValue) const{
  char svalue[MAX_VALUE];

  sprintf( svalue, "%lld", defValue);
  return atoll( GetValue( secname, key, svalue).c_str()); 
}

bool CIniFile::GetValueB(string const secname, string const key, bool const defValue) const {
	string sValue = GetValue( secname, key);
	if(sValue.empty()){
		return defValue;
	}else{
		return sValue == "true" || sValue == "yes";
	}
}

double CIniFile::GetValueF(string const secname, string const key, double const defValue) const
{
  char svalue[MAX_VALUE];

  sprintf( svalue, "%f", defValue);
  return atof( GetValue( secname, key, svalue).c_str()); 
}

// 16 variables may be a bit of over kill, but hey, it's only code.
unsigned CIniFile::GetValueV( string const secname, string const key, const char *format,
			      void *v1, void *v2, void *v3, void *v4,
  			      void *v5, void *v6, void *v7, void *v8,
  			      void *v9, void *v10, void *v11, void *v12,
  			      void *v13, void *v14, void *v15, void *v16)
{
  string   value;
  // va_list  args;
  unsigned nVals;


  value = GetValue( secname, key);
  if ( !value.length())
    return false;
  // Why is there not vsscanf() function. Linux man pages say that there is
  // but no compiler I've seen has it defined. Bummer!
  //
  // va_start( args, format);
  // nVals = vsscanf( value.c_str(), format, args);
  // va_end( args);

  nVals = sscanf( value.c_str(), format,
		  v1, v2, v3, v4, v5, v6, v7, v8,
		  v9, v10, v11, v12, v13, v14, v15, v16);

  return nVals;
}

#if 0
bool CIniFile::WriteFile()
{
  unsigned commentID, sectionID, keyId;
  // Normally you would use ofstream, but the SGI CC compiler has
  // a few bugs with ofstream. So ... fstream used.
  fstream f;

  f.open( path.c_str(), ios::out);
  if ( f.fail())
    return false;

  // Write header m_hdrcomments.
  for ( commentID = 0; commentID < m_hdrcomments.size(); ++commentID)
    f << ';' << m_hdrcomments[commentID] << iniEOL;
  if ( m_hdrcomments.size())
    f << iniEOL;

  // Write sections and values.
  for ( sectionID = 0; sectionID < m_sections.size(); ++sectionID) {
  	if( !m_secnames[sectionID].empty()){
    	f << '[' << m_secnames[sectionID] << ']' << iniEOL;
  	}
    // Comments.
    for ( commentID = 0; commentID < m_sections[sectionID].comments.size(); ++commentID)
      f << ';' << m_sections[sectionID].comments[commentID] << iniEOL;
    // Values.
    for ( keyId = 0; keyId < m_sections[sectionID].keys.size(); ++keyId)
      f << m_sections[sectionID].keys[keyId] << '=' << m_sections[sectionID].values[keyId] << iniEOL;
    f << iniEOL;
  }
  f.close();
  
  return true;
}


bool CIniFile::SetValueI( string const secname, string const key, int const value, bool const create)
{
  char svalue[MAX_VALUE];

  sprintf( svalue, "%d", value);
  return SetValue( secname, key, svalue);
}

bool CIniFile::SetValueF( string const secname, string const key, double const value, bool const create)
{
  char svalue[MAX_VALUE];

  sprintf( svalue, "%f", value);
  return SetValue( secname, key, svalue);
}

bool CIniFile::SetValueV( string const secname, string const key, const char *format, ...)
{
  va_list args;
  char value[MAX_VALUE];

  va_start( args, format);
  vsprintf( value, format, args);
  va_end( args);
  return SetValue( secname, key, value);
}

bool CIniFile::DeleteKey( string const secname, string const key)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return false;

  long keyId = FindKey( unsigned(sectionID), key);
  if ( keyId == noID)
    return false;

  // This looks strange, but is neccessary.
  vector<string>::iterator npos = m_sections[sectionID].keys.begin() + keyId;
  vector<string>::iterator vpos = m_sections[sectionID].values.begin() + keyId;
  m_sections[sectionID].keys.erase( npos, npos + 1);
  m_sections[sectionID].values.erase( vpos, vpos + 1);

  return true;
}

bool CIniFile::DeleteSection( string const secname)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return false;

  // Now hopefully this destroys the vector lists within m_sections.
  // Looking at <vector> source, this should be the case using the destructor.
  // If not, I may have to do it explicitly. Memory leak check should tell.
  // memleak_test.cpp shows that the following not required.
  //m_sections[sectionID].m_secnames.clear();
  //m_sections[sectionID].values.clear();

  vector<string>::iterator npos = m_secnames.begin() + sectionID;
  vector<Section>::iterator    kpos = m_sections.begin() + sectionID;
  m_secnames.erase( npos, npos + 1);
  m_sections.erase( kpos, kpos + 1);

  return true;
}

void CIniFile::Clear()
{
  // This loop not needed. The vector<> destructor seems to do
  // all the work itself. memleak_test.cpp shows this.
  //for ( unsigned i = 0; i < m_sections.size(); ++i) {
  //  m_sections[i].m_secnames.clear();
  //  m_sections[i].values.clear();
  //}
  m_secnames.clear();
  m_sections.clear();
  m_hdrcomments.clear();
}

void CIniFile::AddHeaderComment( string const comment)
{
  m_hdrcomments.resize( m_hdrcomments.size() + 1, comment);
}

string CIniFile::GetHeaderComment( unsigned const commentID) const
{
  if ( commentID < m_hdrcomments.size())
    return m_hdrcomments[commentID];
  return "";
}

bool CIniFile::DeleteHeaderComment( unsigned commentID)
{
  if ( commentID < m_hdrcomments.size()) {
    vector<string>::iterator cpos = m_hdrcomments.begin() + commentID;
    m_hdrcomments.erase( cpos, cpos + 1);
    return true;
  }
  return false;
}

unsigned CIniFile::NumSectionComments( unsigned const sectionID) const
{
  if ( sectionID < m_sections.size())
    return m_sections[sectionID].comments.size();
  return 0;
}

unsigned CIniFile::NumSectionComments( string const secname) const
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return 0;
  return m_sections[sectionID].comments.size();
}

bool CIniFile::AddSectionComment( unsigned const sectionID, string const comment)
{
  if ( sectionID < m_sections.size()) {
    m_sections[sectionID].comments.resize( m_sections[sectionID].comments.size() + 1, comment);
    return true;
  }
  return false;
}

bool CIniFile::AddSectionComment( string const secname, string const comment)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return false;
  return SectionComment( unsigned(sectionID), comment);
}

string CIniFile::GetSectionComment( unsigned const sectionID, unsigned const commentID) const
{
  if ( sectionID < m_sections.size() && commentID < m_sections[sectionID].comments.size())
    return m_sections[sectionID].comments[commentID];
  return "";
}

string CIniFile::GetSectionComment( string const secname, unsigned const commentID) const
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return "";
  return SectionComment( unsigned(sectionID), commentID);
}

bool CIniFile::DeleteSectionComment( unsigned const sectionID, unsigned const commentID)
{
  if ( sectionID < m_sections.size() && commentID < m_sections[sectionID].comments.size()) {
    vector<string>::iterator cpos = m_sections[sectionID].comments.begin() + commentID;
    m_sections[sectionID].comments.erase( cpos, cpos + 1);
    return true;
  }
  return false;
}

bool CIniFile::DeleteSectionComment( string const secname, unsigned const commentID)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return false;
  return DeleteSectionComment( unsigned(sectionID), commentID);
}

bool CIniFile::DeleteSectionComments( unsigned const sectionID)
{
  if ( sectionID < m_sections.size()) {
    m_sections[sectionID].comments.clear();
    return true;
  }
  return false;
}

bool CIniFile::DeleteSectionComments( string const secname)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return false;
  return DeleteSectionComments( unsigned(sectionID));
}
#endif


bool CIniFile::SetValue( string const secname, string const key, string const value, bool const create)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID) {
    if ( create)
      sectionID = long( AddSectionName( secname));
    else
      return false;
  }

  long keyId = FindKey( unsigned(sectionID), key);
  if ( keyId == noID) {
    if ( !create)
      return false;
    m_sections[sectionID].keys.resize( m_sections[sectionID].keys.size() + 1, key);
    m_sections[sectionID].values.resize( m_sections[sectionID].values.size() + 1, value);
  } else
    m_sections[sectionID].values[keyId] = value;

  return true;
}

bool CIniFile::SetValue( unsigned const sectionID, unsigned const keyId, string const value)
{
  if ( sectionID < m_sections.size() && keyId < m_sections[sectionID].keys.size())
    m_sections[sectionID].values[keyId] = value;

  return false;
}

bool CIniFile::AddSectionComment( unsigned const sectionID, string const comment)
{
  if ( sectionID < m_sections.size()) {
    m_sections[sectionID].comments.resize( m_sections[sectionID].comments.size() + 1, comment);
    return true;
  }
  return false;
}

bool CIniFile::AddSectionComment( string const secname, string const comment)
{
  long sectionID = FindSection( secname);
  if ( sectionID == noID)
    return false;
  return AddSectionComment( unsigned(sectionID), comment);
}

void CIniFile::AddHeaderComment( string const comment)
{
  m_hdrcomments.resize( m_hdrcomments.size() + 1, comment);
}


string CIniFile::CheckCase( string s) const
{
  if ( caseInsensitive)
    for ( string::size_type i = 0; i < s.length(); ++i)
      s[i] = tolower(s[i]);
  return s;
}
