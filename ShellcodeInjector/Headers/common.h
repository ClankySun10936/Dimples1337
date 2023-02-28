#pragma once

#include<Windows.h>
#include<stdio.h>
#include<iostream>
std::wstring StringToWString(const std::string& str)
{
    std::wstring wstr(str.length(), L' ');
    std::copy(str.begin(), str.end(), wstr.begin());
    return wstr;
}

std::string WStringToString(const std::wstring& wstr)
{
    std::string str(wstr.length(), ' ');
    std::copy(wstr.begin(), wstr.end(), str.begin());
    return str;
}

void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{

    unsigned char highByte, lowByte;

    for (int i = 2, j = 0; i < sourceLen; i += 4, j++)
    {

        highByte = source[i];
        lowByte = source[i + 1];
        if (highByte >= 'a')
            highByte = highByte - 'a' + 10;
        else
            highByte -= '0';

        if (lowByte >= 'a')
            lowByte = lowByte - 'a' + 10;
        else
            lowByte -= '0';

        dest[j] = (highByte << 4) | lowByte;
    }
    return;
}
void printBuf(LPBYTE pbData, int nSize) {
    for (int i = 0; i < nSize; ++i)
    {
        printf("\\x%x", pbData[i]);
    }
    printf("\n---------------------\n");
}