/**
 * Copyright (C) 2023 Fibocom Corporation.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * @file fibo_flash_parse_xml.c
 * @author bolan.wang@fibocom.com (wangbolan)
 * @brief
 * @version 1.0
 * @date 2023-09-23
 *
 *
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <sys/types.h>
#include <dirent.h>
#include "fibo_flash_main.h"
#include "safe_str_lib.h"

#ifndef EOK
#define EOK (0)
#endif

static xmlChar *carrier_id = NULL;
static xmlChar *fw_version = NULL;
static xmlChar *ap_version = NULL;
static xmlChar *cust_pack = NULL;
static xmlChar *oem_pack_ver = NULL;
static xmlChar *oem_pack_version = NULL;
static xmlChar *dev_ota_image = NULL;
static const int path_len = 500;
static xmlChar *switch_table_file = NULL;


int get_fwinfo(fw_details *fwinfo)
{
    fwinfo->ap_ver = ap_version;
    fwinfo->fw_ver = fw_version;
    fwinfo->cust_pack = cust_pack;
    fwinfo->oem_pack = oem_pack_ver;
    fwinfo->dev_pack = dev_ota_image;

    return 0;
}
static void search_dev_pack(xmlNode *a_node, xmlChar* oemver, xmlChar* wwandevconfid,
    xmlChar* skuid, xmlChar *subsys_id)
{
    xmlNode *cur_node = NULL;
    xmlNode *parent_node = NULL;
    xmlChar *val1 = NULL;
    xmlChar *val2 = NULL;
    xmlChar *prod_id = NULL;
    xmlChar *subsys_match = NULL;
    static xmlChar *oemver_id = NULL;
    int res = -1;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if(XML_ELEMENT_NODE == cur_node->type)
        {
            if(NULL != skuid)
            {
                if(!xmlStrcmp(cur_node->name, (const xmlChar *) "UniqueSkuID"))
                {
                    prod_id = xmlGetProp(cur_node,(const xmlChar*)"ProductID");
                    if(!xmlStrcmp(prod_id, skuid))
                    {
                        oemver_id = xmlGetProp(cur_node,(const xmlChar*)"WwanDeviceConfigID");
                        FIBO_LOG_INFO("match WwanDeviceConfigID by skuid is %s", oemver_id);
                    }
                }
            }

            if(!xmlStrcmp(cur_node->name, (const xmlChar *) "DEVFirmware") &&
               !xmlStrcmp(cur_node->parent->name, (const xmlChar *) "PidVid") &&
               !xmlStrcmp(cur_node->parent->parent->parent->name,(const xmlChar *)"WwanDeviceConfigID"))
            {

                subsys_match = xmlGetProp(cur_node->parent,(const xmlChar*)"Subsysid");
                FIBO_LOG_INFO("subsys_match is %s, Subsysid is %s", subsys_match, subsys_id);
                if (!xmlStrcasecmp(subsys_match, subsys_id))
                {
                    if(strnlen_s(oemver_id, 32) != 0)
                    {
                        val1 = xmlGetProp(cur_node->parent->parent->parent,(const xmlChar*)"ID");
                        if (!xmlStrcmp(val1, oemver_id))
                        {
                            val2 = xmlGetProp(cur_node,(const xmlChar*)"File");
                            FIBO_LOG_INFO("WwanDeviceConfigID is:%s, match WwanDeviceConfigID is:%s, DEV version is:%s",
                                val1, oemver_id, val2);
                            dev_ota_image = val2;
                        }
                    }
                }
           }
        }
            search_dev_pack(cur_node->children,oemver,wwandevconfid,skuid, subsys_id);
    }
}

void find_dev_image(char *docname,xmlChar *oemver, xmlChar* wwandevconfid, xmlChar *skuid,
    xmlChar *subsys_id)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlNodePtr child;
    xmlChar *xmlBuf = NULL;
    int bufferSize;

    doc = xmlParseFile(docname);
    if (doc == NULL )
    {
        fprintf(stderr,"Document not parsed successfully. \n");
        return;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
    }

    search_dev_pack(cur,oemver, wwandevconfid, skuid, subsys_id);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return;
}

static void search_oempack_ver(xmlNode *a_node, xmlChar* oemver)
{
    xmlNode *cur_node = NULL;
    xmlChar *val1 = NULL;
    xmlChar *val2 = NULL;
    xmlChar *val3 = NULL;
    int res = -1;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "Image") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Device"))
            {
                val1 = xmlGetProp(cur_node->parent,(const xmlChar*)"oempackver");
                val2 = xmlGetProp(cur_node->parent,(const xmlChar*)"fw");
                val3 = xmlGetProp(cur_node->parent,(const xmlChar*)"id");

                if (NULL != xmlStrstr(oemver,val1))
                {
                    oem_pack_ver = xmlGetProp(cur_node,(const xmlChar*)"file");
                }

                xmlFree(val1);
                xmlFree(val2);
            }

        }

        search_oempack_ver(cur_node->children,oemver);
    }
}

void find_oem_pack_ver_pkg_info(char *docname,xmlChar *oemver)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlNodePtr child;
    xmlChar *xmlBuf = NULL;
    int bufferSize;

    doc = xmlParseFile(docname);
    if (doc == NULL )
    {
        fprintf(stderr,"Document not parsed successfully. \n");
        return;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
    }

    search_oempack_ver(cur,oemver);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return;
}

static void search_skuid(xmlNode *a_node, const xmlChar *oemver)
{
    xmlNode *cur_node = NULL;
    xmlChar *value = NULL;
    xmlChar *id = NULL;
    xmlNode *parent = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            parent = cur_node->parent->parent;

            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "DEVFirmware") &&
                    !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Standard") &&
                    !xmlStrcmp(parent->name, (const xmlChar *)"WwanDeviceConfigID"))
            {
                value = xmlGetProp(cur_node,(const xmlChar*)"File");
                id  = xmlGetProp(cur_node,(const xmlChar*)"ID");

                FIBO_LOG_INFO("<%s> --%s:%s\n",__func__, value, id);
                xmlFree(id);
                xmlFree(value);
            }
        }

        search_skuid(cur_node->children, oemver);
    }
}

static void search_cid(xmlNode *a_node, const xmlChar *mccmnc)
{
    xmlNode *cur_node = NULL;
    xmlChar *value = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "Item") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"MCCMNCTable"))
            {
                value = xmlGetProp(cur_node,(const xmlChar*)"mccmnc");
                if(!xmlStrcmp(value, mccmnc))
                {
                    carrier_id = xmlNodeGetContent(cur_node);
                    FIBO_LOG_INFO("mccmnc is:%s, carrier id is:%s", value, carrier_id);
                    return;
                }

                xmlFree(value);
            }
        }

        search_cid(cur_node->children, mccmnc);
    }
}

static void search_fw_version(xmlNode *a_node, const xmlChar *carrier_id, const xmlChar *subsys_id)
{
    xmlNode *cur_node = NULL;
    xmlChar *value = NULL;
    xmlChar *subsys_match = NULL;
    xmlNode *parentNode = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if(cur_node->type == XML_ELEMENT_NODE)
        {
            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "MDFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Carrier"))
            {
                parentNode = cur_node->parent->parent->parent;
                subsys_match =  xmlGetProp(parentNode,(const xmlChar*)"Subsysid");

                 if (!xmlStrcasecmp(subsys_match, subsys_id))
                 {
                        value = xmlGetProp(cur_node->parent,(const xmlChar*)"id");
                        if(!xmlStrcmp(value, carrier_id))
                        {
                            fw_version = xmlGetProp(cur_node,(const xmlChar*)"File");
                            FIBO_LOG_INFO("carrier id is:%s, subSysid is:%s, MD version is:%s",
                                value, subsys_id, fw_version);
                        }

                        xmlFree(value);
                 }

                 xmlFree(subsys_match);
            }

            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "APFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Carrier"))
            {
                    parentNode = cur_node->parent->parent->parent;
                    subsys_match =  xmlGetProp(parentNode,(const xmlChar*)"Subsysid");

                if(!xmlStrcasecmp(subsys_match, subsys_id))
                {
                    value = xmlGetProp(cur_node->parent,(const xmlChar*)"id");
                    if(!xmlStrcmp(value, carrier_id))
                    {
                        ap_version = xmlGetProp(cur_node,(const xmlChar*)"File");
                        FIBO_LOG_INFO("carrier id is:%s, subSysid is:%s, AP version is:%s",
                            value, subsys_id, ap_version);
                    }

                    xmlFree(value);
                }

                 xmlFree(subsys_match);
            }

            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "OPFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Carrier"))
            {
                parentNode = cur_node->parent->parent->parent;
                subsys_match =  xmlGetProp(parentNode,(const xmlChar*)"Subsysid");

                 if (!xmlStrcasecmp(subsys_match, subsys_id))
                 {
                    value = xmlGetProp(cur_node->parent,(const xmlChar*)"id");
                    if(!xmlStrcmp(value, carrier_id))
                    {
                        cust_pack = xmlGetProp(cur_node,(const xmlChar*)"Ver");
                        FIBO_LOG_INFO("carrier id is:%s, subSysid is:%s, OP version is:%s",
                            value, subsys_id, cust_pack);
                    }

                    xmlFree(value);
                }

                    xmlFree(subsys_match);
            }

            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "OEMFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"CustModel"))
            {
                 parentNode = cur_node->parent->parent->parent;
                 subsys_match =  xmlGetProp(parentNode,(const xmlChar*)"Subsysid");

                 if(!xmlStrcasecmp(subsys_match, subsys_id))
                 {
                     oem_pack_ver = xmlGetProp(cur_node,(const xmlChar*)"File");
                     oem_pack_version = xmlGetProp(cur_node,(const xmlChar*)"Ver");

                     FIBO_LOG_INFO("subSysid is:%s, OEM version is:%s", subsys_id, oem_pack_version);
                 }

                 xmlFree(subsys_match);
            }
        }

        search_fw_version(cur_node->children, carrier_id, subsys_id);
    }
}

void find_fw_version(char* docname, xmlChar* carrier_id, xmlChar* subsys_id)
{
    xmlDocPtr doc;
    xmlNodePtr cur;

    doc = xmlParseFile(docname);
    if (doc == NULL )
    {
        fprintf(stderr,"Document not parsed successfully.\n");
        FIBO_LOG_ERROR("Document not parsed successfully.\n");
        return;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
    }

    search_fw_version(cur, carrier_id, subsys_id);
}

static void search_fw_version_default(xmlNode *a_node, const xmlChar *carrier_id, const xmlChar *subsys_id)
{
    xmlNode *cur_node = NULL;
    xmlChar *value = NULL;
    xmlChar *subsys_id_val = NULL;
    xmlNode *parentNode = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "MDFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Carrier"))
            {
                 value = xmlGetProp(cur_node->parent,(const xmlChar*)"id");
                 if(!xmlStrcmp(value, "default"))
                 {
                     fw_version = xmlGetProp(cur_node,(const xmlChar*)"File");
                     FIBO_LOG_INFO("MD version is:%s", fw_version);
                 }

                 xmlFree(value);
            }

            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "APFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Carrier"))
            {
                 value = xmlGetProp(cur_node->parent,(const xmlChar*)"id");
                 if(!xmlStrcmp(value, "default"))
                 {
                    ap_version = xmlGetProp(cur_node,(const xmlChar*)"File");
                    FIBO_LOG_INFO("AP version is:%s", ap_version);
                 }

                 xmlFree(value);
            }

            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "OPFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"Carrier"))
            {
                 value = xmlGetProp(cur_node->parent,(const xmlChar*)"id");
                 if(!xmlStrcmp(value, "default"))
                 {
                    cust_pack = xmlGetProp(cur_node,(const xmlChar*)"Ver");
                    FIBO_LOG_INFO("OP version is:%s", cust_pack);
                 }

                xmlFree(value);
            }


            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "OEMFirmware") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"CustModel"))
            {
                parentNode = cur_node->parent->parent->parent;
                subsys_id_val = xmlGetProp(parentNode, (const xmlChar *) "Subsysid");

                if(!xmlStrcmp(subsys_id_val, "default"))
                {
                    oem_pack_ver = xmlGetProp(cur_node,(const xmlChar*)"File");
                    oem_pack_version = xmlGetProp(cur_node,(const xmlChar*)"Ver");
                    FIBO_LOG_INFO("OEM version is:%s", oem_pack_version);
                }

                xmlFree(subsys_id_val);
            }

        }

        search_fw_version_default(cur_node->children, carrier_id, subsys_id);
    }
}

void find_fw_version_default(char* docname, xmlChar* carrier_id, xmlChar* subsys_id )
{
     xmlDocPtr doc;
     xmlNodePtr cur;

     doc = xmlParseFile(docname);
     if (doc == NULL )
     {
        fprintf(stderr,"Document not parsed successfully. \n");
        return;
     }

     cur = xmlDocGetRootElement(doc);
     if (cur == NULL)
     {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
     }

     search_fw_version_default(cur, carrier_id, subsys_id);
}


void find_carrier_id(char* docname,xmlChar* mccmnc)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlNodePtr child;
    xmlChar *xmlBuf = NULL;
    int bufferSize;

    doc = xmlParseFile(docname);
    if (doc == NULL )
    {
        fprintf(stderr,"Document not parsed successfully. \n");
        return;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
    }

    search_cid(cur, mccmnc);
    xmlCleanupParser();
    return;
}

static void search_switchtbl_using_oemver(xmlNode *a_node, const xmlChar *oemver, const xmlChar *subsys_id)
{
    xmlNode *cur_node = NULL;
    xmlNode *childNode = NULL;
    xmlChar *ver = NULL;
    xmlChar *file = NULL;
    xmlNode *subsysNode = NULL;
    xmlChar *subsys_val = NULL;
    int ret;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (!xmlStrcmp(cur_node->name, (const xmlChar *) "Switch_table") &&
                !xmlStrcmp(cur_node->parent->name,(const xmlChar *)"OEMFirmware"))
            {
                subsysNode = cur_node->parent->parent->parent->parent;

                if(subsysNode != NULL)
                {
                    subsys_val = xmlGetProp(subsysNode,(const xmlChar*)"Subsysid");
                    FIBO_LOG_INFO("subsys_val is %s, Subsysid is %s", subsys_val, subsys_id);
                    if(!xmlStrcasecmp(subsys_val, subsys_id))
                    {
                        file = xmlGetProp(cur_node,(const xmlChar*)"File");
                        ver = xmlGetProp(cur_node->parent,(const xmlChar*)"Ver");

                        if(!xmlStrcmp(ver, oemver))
                        {
                            switch_table_file = file;
                        }
                        else
                        {
                            switch_table_file = file;
                        }
                    }
                }

                xmlFree(ver);
            }
        }

        search_switchtbl_using_oemver(cur_node->children, oemver, subsys_id);
    }
}

void find_switch_table(char *docname,xmlChar *oemver, xmlChar *subsys_id)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlNodePtr child;
    xmlChar *xmlBuf = NULL;
    int bufferSize;
    FIBO_LOG_INFO("entry");

    doc = xmlParseFile(docname);
    if (doc == NULL )
    {
        fprintf(stderr,"Document not parsed successfully. \n");
        FIBO_LOG_ERROR("Document not parsed successfully.\n");
        return;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
    }

    search_switchtbl_using_oemver(cur, oemver, subsys_id);
    xmlCleanupParser();
    return;
}

int parse_version_info(char* mccmnc_id, char* sku_id, char* subsys_id,
    char* oemver, char* wwandevconfid,fw_details *fw_ver)
{
    char *docname = NULL;
    xmlChar *skuId = NULL;
    xmlChar *mccmnc = NULL;
    xmlChar *oem_pkg_ver = NULL;
    int indicator;
    char fwswitch_table[126] = {0};
    char package_info_xml[126] = {0};
    char wwan_devid_map_table_xml[126] = {0};

    FIBO_LOG_INFO("begin parse version info from XMLs");

    find_path_of_file("FwPackageInfo.xml", FWPACKAGE_PATH, package_info_xml);
    find_path_of_file("WwanDeviceIdImageMappingTable.xml", DEV_PKG_PATH, wwan_devid_map_table_xml);

    FIBO_LOG_INFO("oemver is %s", oemver); //read from device

    if(strnlen_s(package_info_xml, 32) != 0)
    {
        find_switch_table(package_info_xml, oemver, subsys_id);
    }

    if(strnlen_s(package_info_xml, 32) != 0)
    {
        find_path_of_file(switch_table_file, FWPACKAGE_PATH, fwswitch_table);
    }

    FIBO_LOG_INFO("find switch table:%s", switch_table_file);

    if(strnlen_s(fwswitch_table, 32) != 0)
    {
       find_carrier_id(fwswitch_table,mccmnc_id);
    }

    if(NULL == carrier_id)
    {
        carrier_id = "default";
    }

    FIBO_LOG_INFO("find carrier id by mccmnc is:%s", carrier_id);

    if(EOK == strcmp_s(subsys_id,strnlen_s(subsys_id,32),"default",&indicator))
    {
        if(0 == indicator)
        {
            if(strnlen_s(package_info_xml, 32) != 0)
            {
                FIBO_LOG_INFO("matching default version");
                find_fw_version_default(package_info_xml, carrier_id, subsys_id);
            }
        }
        else
        {
            if(strnlen_s(package_info_xml, 32) != 0)
            {
                FIBO_LOG_INFO("not default, carrier id is:%s, subSysid is:%s", carrier_id, subsys_id);
                find_fw_version(package_info_xml, carrier_id, subsys_id);
            }
        }
    }

    if(strnlen_s(wwan_devid_map_table_xml, 32) != 0)
    {
       find_dev_image(wwan_devid_map_table_xml,oem_pack_version, wwandevconfid, sku_id, subsys_id);
    }

    fw_ver->fw_ver = (const char* )fw_version;
    fw_ver->cust_pack = (const char* )cust_pack;
    fw_ver->oem_pack = (const char* )oem_pack_version;
    fw_ver->dev_pack = (const char* )dev_ota_image;
    fw_ver->ap_ver = (const char* )ap_version;

    FIBO_LOG_INFO("MD version:%s, OP version is:%s, OEM version is:%s, DEV version is:%s, AP version is:%s\n",
        fw_ver->fw_ver, fw_ver->cust_pack, fw_ver->oem_pack, fw_ver->dev_pack, fw_ver->ap_ver);

    return 0;
}

void find_path_of_file(const char* file, char* directory, char *pathoffile)
{
    char fullpath[path_len];
    struct dirent *dp = NULL;
    int indicator1 = 0;
    int indicator2 = 0;
    int indFileMatch = 0;

    //Path of firmware update directory
    DIR *direcP = opendir(directory);

    // Check if the firmware update directory exist.
    if (!direcP)
    {
        return;
    }

    while ((dp = readdir(direcP)) != NULL)
    {
    if(strcmp_s(dp->d_name,strnlen_s(dp->d_name,32),".",&indicator1) == EOK  &&
        strcmp_s(dp->d_name,strnlen_s(dp->d_name,32),"..",&indicator2) == EOK )
        {
            if( indicator1 != 0 && indicator2 != 0)
            {
                // Construct new path from our base path
                strcpy_s(fullpath,path_len,directory);
                strcat_s(fullpath,path_len, "/");
                strcat_s(fullpath,path_len, dp->d_name);
                find_path_of_file(file,fullpath, pathoffile);

                if(strcmp_s(dp->d_name,strnlen_s(dp->d_name,64),file,&indFileMatch) == EOK)
                {
                    if(indFileMatch == 0)
                    {
                        strcpy_s(pathoffile,path_len,fullpath);
                        closedir(direcP);
                        return;
                    }
                }
            }
        }
    }

    closedir(direcP);
}