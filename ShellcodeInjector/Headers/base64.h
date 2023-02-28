
#ifndef __BASE64__
#define __BASE64__

#include <string>

using std::string;

class Base64
{
public:
    static string encode(string);
    static string decode(string);
    static int getIndex(char);
    static const char list[65];
};

const char Base64::list[65] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T',
        'U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7',
        '8','9','+','/','='
};

string Base64::encode(string s)
{
    int len = s.size(), tmpLen;
    string enStr;

    tmpLen = len / 3 * 3;
    for (int i = 0; i < tmpLen; i += 3)
    {
        enStr += Base64::list[s[i] >> 2];
        enStr += Base64::list[(s[i] & 0x3) << 4 | (s[i + 1] >> 4)];
        enStr += Base64::list[(s[i + 1] & 0xF) << 2 | (s[i + 2]) >> 6];
        enStr += Base64::list[s[i + 2] & 0x3f];
    }
    if (tmpLen < len)
    {
        enStr += Base64::list[s[tmpLen] >> 2];
        if (tmpLen + 1 == len)
        {
            enStr += Base64::list[((0x3 & s[tmpLen]) << 4)];
            enStr += "=";
        }
        else
        {
            enStr += Base64::list[((0x3 & s[tmpLen]) << 4) | ((s[tmpLen + 1] & 0xF0) >> 4)];
            enStr += Base64::list[(s[tmpLen + 1] & 0x0F) << 2];
        }
        enStr += "=";
    }

    return enStr;
}

string Base64::decode(string s)
{
    string deStr;
    int len = s.size() / 4 * 4;  //avoid out of range
    for (int i = 0; i < len; i += 4)
    {
        deStr += (char)((Base64::getIndex(s[i]) & 0x3F) << 2 | (Base64::getIndex(s[i + 1]) & 0x30) >> 4);
        deStr += (char)((Base64::getIndex(s[i + 1]) & 0xF) << 4 | (Base64::getIndex(s[i + 2]) & 0x3C) >> 2);
        deStr += (char)((Base64::getIndex(s[i + 2]) & 0x3) << 6 | (Base64::getIndex(s[i + 3]) & 0x3F));
    }
    return deStr;
}

int Base64::getIndex(char c)
{
    for (int i = 0; i < 65; ++i)
        if (c == Base64::list[i])
            return i;
    return -1;
}

#endif