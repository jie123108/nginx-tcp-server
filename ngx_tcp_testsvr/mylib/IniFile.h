#ifndef __BASELIB_INI_FILE__H_
#define __BASELIB_INI_FILE__H_
/*==============================================================
 * FileName:      IniFile.h
 * Version:        1.0
 * Created by:    liuxj
 * Copyright (c) 2011 qvod Corporation.  All Rights Reserved. 
 *--------------------------------------------------------------
 * Description:   
 *      实现对Ini文件的读和写。
 *=============================================================*/

// C++ Includes
#include <string>
#include <vector>
using namespace std;

// C Includes
#include <stdlib.h>

//段名称最大长度。
#define MAX_SEC_NAME   128

#define MAX_KEY  128
#define MAX_VALUE 2048

class CIniFile  
{
public:
	enum errors{ noID = -1};

	/*--------------------------------------------------------------
	 * 功能：		构造函数。
	 * 参数：		iniPath ini配置文件名。
	 * 返回值：	无。
	 *-------------------------------------------------------------*/
	CIniFile(string const iniPath = "");
	virtual ~CIniFile(){}

	/*--------------------------------------------------------------
	 * 功能：		设置成大小写敏感的[指secionName及key], 默认为不敏感的。
	 * 参数：		无。
	 * 返回值：	无。
	 *-------------------------------------------------------------*/
	void CaseSensitive(){
		caseInsensitive = false;
	}
	
	/*--------------------------------------------------------------
	 * 功能：		设置成大小写不敏感的。 默认为不敏感的。
	 * 参数：		无。
	 * 返回值：	无。
	 *-------------------------------------------------------------*/
	void CaseInsensitive(){
		caseInsensitive = true;
	}

	string GetPath() const{
		return path;
	}
	/*--------------------------------------------------------------
	 * 功能：		设置新的配置文件路径。
	 * 参数：		newPath, 新的文件名路径。
	 * 返回值：	无。
	 *-------------------------------------------------------------*/
	void SetPath(string const newPath){
		path = newPath;
	}

	/*--------------------------------------------------------------
	 * 功能：		读取并解析配置文件。
	 * 参数：		无。
	 * 返回值：	读取状态。true表示成功，false表示失败。
	 *-------------------------------------------------------------*/
	bool ReadFile();

	/*--------------------------------------------------------------
	 * 功能：		查找指定的段[section]
	 * 参数：		secname, 要找到的段的名称。
	 * 返回值：	返回该段的ID, 如果未找到返回noID。
	 *-------------------------------------------------------------*/
	long FindSection( string const secname) const;

	/*--------------------------------------------------------------
	 * 功能：		查找指定的键[Key]
	 * 参数：		sectionID, 要找到的段的ID。
	 *			key, 要找到的Key。
	 * 返回值：	返回该键的ID, 如果未找到返回noID。
	 *-------------------------------------------------------------*/
	long FindKey( unsigned const sectionID, string const key) const;

	/*--------------------------------------------------------------
	 * 功能：		获取当前文件的段的总数。
	 * 参数：		无。
	 * 返回值：	返回段的总数。
	 *-------------------------------------------------------------*/
	unsigned GetNumSections() const{return m_secnames.size();}

	/*--------------------------------------------------------------
	 * 功能：		添加一个段[到内存]
	 * 参数：		secname, 添加的段的名称。
	 * 返回值：	新添加的段的ID。
	 *-------------------------------------------------------------*/
	unsigned AddSectionName( string const secname);

	/*--------------------------------------------------------------
	 * 功能：		获取指定ID对应的段名称。
	 * 参数：		sectinID 段的ID。
	 * 返回值：	返回段名称。
	 *-------------------------------------------------------------*/
	string GetSectionName( unsigned const sectionID) const;

	unsigned GetNumKeys( unsigned const sectionID);
	/*--------------------------------------------------------------
	 * 功能：		获取指定的段下面有多少Key.
	 * 参数：		secname 段名称。
	 * 返回值：	返回secname下段的数量。
	 *-------------------------------------------------------------*/
	unsigned GetNumKeys( string const secname);

	/*--------------------------------------------------------------
	 * 功能：		获取指定的段下面所有的Key.
	 * 参数：		secname 段名称。
	 * 返回值：	返回secname下所有的key
	 *-------------------------------------------------------------*/
	vector<string>* GetKeys(string const secname);
	
	/*--------------------------------------------------------------
	 * 功能：		读取secname下key对应的值。重载的函数分别可以读取Int型，Bool型，浮点型等。
	 * 参数：		secname 段名称。
	 *			key 为键名称。
	 *			defValue为默认值。
	 * 返回值：	返回读取到的值。
	 *-------------------------------------------------------------*/
	string GetValue(string const secname, string const key, string const defValue = "") const; 
	int    GetValueI(string const secname, string const key, int const defValue = 0) const;
	bool   GetValueB(string const secname, string const key, bool const defValue = false) const;
	double   GetValueF(string const secname, string const key, double const defValue = 0.0) const;
	long long GetValueLL(string const secname, string const key, long long const defValue=0) const;
	 
	/*--------------------------------------------------------------
	 * 功能：		按format指定的格式读取一个或者多个值。format中的格式与scanf,sscanf等相同。
	 * 参数：		secname, 要读取的段名称。
	 *			key, 要读取的Key。
	 *			format, 格式串，与scanf格式串相同。
	 *			v1..v16 为指针。
	 * 返回值：	返回读取的值的数量。
	 *-------------------------------------------------------------*/
	unsigned GetValueV( string const secname, string const key, const char *format,
	  void *v1 = 0, void *v2 = 0, void *v3 = 0, void *v4 = 0,
	      void *v5 = 0, void *v6 = 0, void *v7 = 0, void *v8 = 0,
	      void *v9 = 0, void *v10 = 0, void *v11 = 0, void *v12 = 0,
	      void *v13 = 0, void *v14 = 0, void *v15 = 0, void *v16 = 0);
#if 0
	// Writes data stored in class to ini file.
	/*--------------------------------------------------------------
	 * 功能：		保存配置文件, 对配置的修改只有WriteFile后才生效。
	 * 参数：		无。
	 * 返回值：	保存状态。true表示成功，false表示失败。
	 *-------------------------------------------------------------*/
	bool WriteFile(); 

	/*--------------------------------------------------------------
	 * 功能：		删除所有(内存中的)配置。
	 * 参数：		无。
	 * 返回值：	无。
	 *-------------------------------------------------------------*/
	void Clear();

	/*--------------------------------------------------------------
	 * 功能：		设置一个值。重载的几个函数分别可以设置Int,Bool,Float等类型的值。
	 * 参数：		secname, 段名称。
	 *			key, 键名称
	 *			value, 值。
	 *			create, 当secname不存在时，如果create为true则会创建该section,否则会失败。
	 * 返回值：	设置状态。
	 *-------------------------------------------------------------*/
	bool SetValue( string const secname, string const key, string const value, bool const create = true);
	bool SetValueI( string const secname, string const key, int const value, bool const create = true);
	bool SetValueB( string const secname, string const key, bool const value, bool const create = true) {
	return SetValue( secname, key, value?"true":"false", create);
	}
	bool SetValueF( string const secname, string const key, double const value, bool const create = true);

	/*--------------------------------------------------------------
	 * 功能：		按指定的格式设置一个或者多个值。
	 * 参数：		无。
	 * 返回值：	保存状态。
	 *-------------------------------------------------------------*/
	bool SetValueV( string const secname, string const key, const char *format, ...);

	/*--------------------------------------------------------------
	 * 功能：		删除一个键值。
	 * 参数：		secname，段的名称。 
	 *			key，要删除的键。
	 * 返回值：	删除状态， true表示删除成功，false表示删除失败。
	 *-------------------------------------------------------------*/
	bool DeleteKey( string const secname, string const key);

	// Deletes specified Section and all values contained within.
	// Returns true if Section existed and deleted, false otherwise.
	/*--------------------------------------------------------------
	 * 功能：		删除一个段。
	 * 参数：		secname 要删除的段的名称。
	 * 返回值：	删除状态， true表示删除成功，false表示删除失败。
	 *-------------------------------------------------------------*/
	bool DeleteSection(string secname);

	
#endif
	bool SetValue( string const secname, string const key, string const value, bool const create = true);

	void     AddHeaderComment( string const comment);
	bool     AddSectionComment( unsigned const sectionID, string const comment);
	bool     AddSectionComment( string const secname, string const comment);

protected:
	string GetValue( unsigned const sectionID, unsigned const keyId, string const defValue = "") const;
	bool SetValue( unsigned const sectionID, unsigned const keyId, string const value);

private:
	bool   caseInsensitive;
	string path;
	struct Section {
		vector<string> keys;
		vector<string> values; 
		vector<string> comments; //section comments.
	};
	vector<Section> m_sections; 
	vector<string> m_secnames; 
	vector<string> m_hdrcomments;
	string CheckCase( string s) const;
	
};

#endif
