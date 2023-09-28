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
 * @file fibo_xml_parse.c
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/


#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include "fibo_parse_xml.h"
#include "cfg_log.h"

bool fibo_parse_esim_xml_data(char *filename, esim_xml_parse_rule_t *xmldata,
                             struct list_head *list_sku, struct list_head *list_mcc)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    xmlChar *data = NULL;
    if (NULL == filename || NULL == xmldata || NULL == list_sku || NULL == list_mcc)
    {
        CFG_LOG_ERROR("input para error ,exit");
        return false;
    }
    CFG_LOG_DEBUG("filename:%s", filename);
    doc = xmlParseFile(filename);
    if (NULL == doc)
    {
        CFG_LOG_ERROR("esim xml parse get file error!");
        return false;
    }
    node = xmlDocGetRootElement(doc);
    if (NULL == node)
    {
        CFG_LOG_ERROR("esim xml parse get root error!");
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(node->name, (const xmlChar *)"EsimDiableTable"))
    {
        CFG_LOG_ERROR("esim xml parse node error!");
        xmlFreeDoc(doc);
        return false;
    }
    node = node->xmlChildrenNode;
    while (NULL != node)
    {
        if (!xmlStrcmp(node->name, (const xmlChar *)"TableEnableFlag"))
        {
            data = xmlGetProp(node, "FlagValue");
            if (0 == strcmp(data, "true"))
            {
                xmldata->esim_enable = true;
            }
            else
            {
                xmldata->esim_enable = false;
            }
            xmlFree(data);
            // CFG_LOG_DEBUG("esim_enable:%d\n", xmldata->esim_enable);
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"CustPath"))
        {
            data = xmlGetProp(node, "RegistryPath");
            if (strlen(data))
            {
                strncpy(xmldata->SystemSKU_path, data, strlen(data));
            }
            xmlFree(data);
            // CFG_LOG_DEBUG("SystemSKU_path:%s", xmldata->SystemSKU_path);
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"MatchType"))
        {
            data = xmlGetProp(node, "SelectTypeName");
            if (strlen(data))
            {
                strncpy(xmldata->SelectType, data, strlen(data));
            }
            xmlFree(data);
            CFG_LOG_DEBUG("SelectType:%s", xmldata->SelectType);

            xmlNodePtr type_node = node->xmlChildrenNode;
            while (NULL != type_node)
            {
                if (!xmlStrcmp(type_node->name, (const xmlChar *)"Type"))
                {
                    data = xmlGetProp(type_node, "name");
                    if (0 == strcmp(xmldata->SelectType, data))
                    {
                        strncpy(xmldata->selet_method.name, data, strlen(data));
                        xmlFree(data);
                        data = xmlGetProp(type_node, BAD_CAST "num");
                        if (NULL != data)
                        {
                            xmldata->selet_method.num = atoi(data);
                            xmlFree(data);
                        }
                        data = xmlGetProp(type_node, BAD_CAST "start");
                        if (NULL != data)
                        {
                            xmldata->selet_method.start = atoi(data);
                            xmlFree(data);
                        }
                        data = xmlGetProp(type_node, BAD_CAST "end");
                        if (NULL != data)
                        {
                            xmldata->selet_method.end = atoi(data);
                            xmlFree(data);
                        }
                        CFG_LOG_DEBUG("node_name:%s,num:%d,start:%d,end:%d", xmldata->selet_method.name, (int)xmldata->selet_method.num,
                                      (int)xmldata->selet_method.start, (int)xmldata->selet_method.end);
                    }
                }
                type_node = type_node->next;
            }
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"SKU_BlackList"))
        {
            xmlNodePtr sku_node = node->xmlChildrenNode;
            while (NULL != sku_node)
            {
                if (!xmlStrcmp(sku_node->name, (const xmlChar *)"SKU"))
                {
                    fibo_sku_black_xml_t *sku_black = NULL;
                    data = xmlGetProp(sku_node, "SKUValue");
                    if (NULL != data)
                    {
                        sku_black = malloc(sizeof(fibo_sku_black_xml_t));
                        if (NULL != sku_black)
                        {
                            memset(sku_black, 0, sizeof(fibo_sku_black_xml_t));
                            strncpy(sku_black->sku, data, strlen(data));
                            list_add_tail(&sku_black->list, list_sku);
                            xmlFree(data);
                            // CFG_LOG_DEBUG("sku_black_list:%s", sku_black->sku);
                        }
                        else
                        {
                            CFG_LOG_ERROR("get memory error!");
                            xmlFreeDoc(doc);
                            return false;
                        }
                    }
                }
                sku_node = sku_node->next;
            }
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"IMSI_BlackList"))
        {
            xmlNodePtr mcc_node = node->xmlChildrenNode;
            while (NULL != mcc_node)
            {
                if (!xmlStrcmp(mcc_node->name, (const xmlChar *)"MCCMNC"))
                {
                    fibo_mcc_black_xml_t *mcc_black = NULL;
                    data = xmlGetProp(mcc_node, "MCCMNCValue");
                    if (NULL != data)
                    {
                        mcc_black = malloc(sizeof(fibo_mcc_black_xml_t));
                        if (NULL != mcc_black)
                        {
                            memset(mcc_black, 0, sizeof(fibo_mcc_black_xml_t));
                            strncpy(mcc_black->mcc, data, strlen(data));
                            list_add_tail(&mcc_black->list, list_mcc);
                            xmlFree(data);
                            CFG_LOG_DEBUG("mcc_black_list:%s", mcc_black->mcc);
                        }
                        else
                        {
                            CFG_LOG_ERROR("get memory error!");
                            xmlFreeDoc(doc);
                            return false;
                        }
                    }
                }
                mcc_node = mcc_node->next;
            }
        }
        node = node->next;
    }
    xmlFreeDoc(doc);
    return true;
}

bool fibo_parse_region_mapping_data(char *filename, char *parse_ver, char *version, struct list_head *select_rule_list,
                                   struct list_head *sar_custom_list)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    xmlChar *data = NULL;
    if (NULL == filename || NULL == version || NULL == select_rule_list || NULL == sar_custom_list)
    {
        CFG_LOG_ERROR("input para error ,exit");
        return false;
    }
    CFG_LOG_DEBUG("filename:%s", filename);
    doc = xmlParseFile(filename);
    if (NULL == doc)
    {
        CFG_LOG_ERROR("esim xml parse get file error!");
        return false;
    }
    node = xmlDocGetRootElement(doc);
    if (NULL == node)
    {
        CFG_LOG_ERROR("esim xml parse get root error!");
        xmlFreeDoc(doc);
        return false;
    }
    CFG_LOG_DEBUG("node:%s", (char *)node->name);
    if (xmlStrcmp(node->name, (const xmlChar *)"RegionSwitchTable"))
    {
        CFG_LOG_ERROR("esim xml parse node error!");
        xmlFreeDoc(doc);
        return false;
    }
    node = node->xmlChildrenNode;
    while (NULL != node)
    {
        if (!xmlStrcmp(node->name, (const xmlChar *)"RegionSwitch"))
        {
            data = xmlGetProp(node, "ver");
            if (NULL != data)
            {
                if (0 != strcmp(parse_ver, data))
                {
                    xmlFree(data);
                    continue;
                }
                else
                {
                    strncpy(version, data, strlen(data));
                    xmlFree(data);
                    CFG_LOG_DEBUG("version:%s", version);
                    xmlNodePtr select_node = node->xmlChildrenNode;
                    while (NULL != select_node)
                    {
                        // CFG_LOG_DEBUG("select_node:%s", (char *)select_node->name);
                        if (!xmlStrcmp(select_node->name, (const xmlChar *)"SelectionRule"))
                        {
                            xmlNodePtr rule_node = select_node->xmlChildrenNode;
                            while (NULL != rule_node)
                            {
                                // CFG_LOG_DEBUG("rule_node:%s", (char *)rule_node->name);
                                if (!xmlStrcmp(rule_node->name, (const xmlChar *)"Region"))
                                {
                                    fibo_select_rule_xml_t *rule_list = NULL;
                                    rule_list = malloc(sizeof(fibo_select_rule_xml_t));
                                    if (NULL != rule_list)
                                    {
                                        memset(rule_list, 0, sizeof(fibo_select_rule_xml_t));
                                        data = xmlGetProp(rule_node, "mcc");
                                        if (NULL != data)
                                        {
                                            strncpy(rule_list->mcc, data, strlen(data));
                                            xmlFree(data);
                                        }
                                        data = xmlGetProp(rule_node, "Regulatory");
                                        if (NULL != data)
                                        {
                                            strncpy(rule_list->regulatory, data, strlen(data));
                                            xmlFree(data);
                                        }
                                        data = xmlGetProp(rule_node, "Country");
                                        if (NULL != data)
                                        {
                                            strncpy(rule_list->country, data, strlen(data));
                                            xmlFree(data);
                                        }
                                        list_add_tail(&rule_list->list, select_rule_list);
                                        // CFG_LOG_DEBUG("mcc:%s,Regulatory:%s,Country:%s", rule_list->mcc, rule_list->regulatory, rule_list->country);
                                    }
                                    else
                                    {
                                        CFG_LOG_ERROR("get memory error!");
                                        xmlFreeDoc(doc);
                                        return false;
                                    }
                                }
                                rule_node = rule_node->next;
                            }
                        }
                        if (!xmlStrcmp(select_node->name, (const xmlChar *)"SarFunctionCustom"))
                        {
                            xmlNodePtr custom_node = select_node->xmlChildrenNode;
                            while (NULL != custom_node)
                            {
                                // CFG_LOG_DEBUG("custom_node:%s", (char *)custom_node->name);
                                if (!xmlStrcmp(custom_node->name, (const xmlChar *)"SarSwitch"))
                                {
                                    fibo_sar_custom_t *custom_list = NULL;
                                    custom_list = malloc(sizeof(fibo_sar_custom_t));
                                    if (NULL != custom_list)
                                    {
                                        memset(custom_list, 0, sizeof(fibo_sar_custom_t));
                                        data = xmlGetProp(custom_node, "Regulatory");
                                        if (NULL != data)
                                        {
                                            strncpy(custom_list->regulatory, data, strlen(data));
                                            xmlFree(data);
                                        }
                                        data = xmlGetProp(custom_node, "SAR_TYPE");
                                        if (NULL != data)
                                        {
                                            strncpy(custom_list->sar_type, data, strlen(data));
                                            xmlFree(data);
                                        }
                                        data = xmlGetProp(custom_node, "DB_OFFSET_Enable");
                                        if (NULL != data)
                                        {
                                            strncpy(custom_list->db_offset_enable, data, strlen(data));
                                            xmlFree(data);
                                        }
                                        list_add_tail(&custom_list->list, sar_custom_list);
                                        // CFG_LOG_DEBUG("Regulatory:%s,SAR_TYPE:%s,DB_OFFSET_Enable:%s", custom_list->regulatory,\
                                                      custom_list->sar_type, custom_list->db_offset_enable);
                                    }
                                    else
                                    {
                                        CFG_LOG_ERROR("get memory error!");
                                        xmlFreeDoc(doc);
                                        return false;
                                    }
                                }
                                custom_node = custom_node->next;
                            }
                        }
                        select_node = select_node->next;
                    }
                }
            }
            else
            {
                xmlFreeDoc(doc);
                return false;
            }
        }
        node = node->next;
    }
    xmlFreeDoc(doc);
    return true;
}

bool fibo_parse_devicemode_static_data(char *filename, devicemode_static_xml_parse_t *xmldata)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    xmlChar *data = NULL;
    if (NULL == filename || NULL == xmldata)
    {
        CFG_LOG_ERROR("input para error ,exit");
        return false;
    }
    CFG_LOG_DEBUG("filename:%s", filename);
    doc = xmlParseFile(filename);
    if (NULL == doc)
    {
        CFG_LOG_ERROR("devicemode xml parse get file error!");
        return false;
    }
    node = xmlDocGetRootElement(doc);
    if (NULL == node)
    {
        CFG_LOG_ERROR("devicemode xml parse get root error!");
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(node->name, (const xmlChar *)"SarAntTableIndex"))
    {
        CFG_LOG_ERROR("devicemode xml parse node error!");
        xmlFreeDoc(doc);
        return false;
    }
    node = node->xmlChildrenNode;
    while (NULL != node)
    {
        if (!xmlStrcmp(node->name, (const xmlChar *)"TableEnableFlag"))
        {
            data = xmlGetProp(node, "FlagValue");
            if (0 == strcmp(data, "true"))
            {
                xmldata->select_index_enable = true;
            }
            else
            {
                xmldata->select_index_enable = false;
            }
            xmlFree(data);
            CFG_LOG_DEBUG("esim_enable:%d", xmldata->select_index_enable);
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"WwanDeviceConfigureIDTable"))
        {
            xmlNodePtr idable_node = node->xmlChildrenNode;
            while (NULL != idable_node)
            {
                if (!xmlStrcmp(idable_node->name, (const xmlChar *)"CustProductNamePathToUniqueSkuID"))
                {
                    data = xmlGetProp(idable_node, "CustProductNamePathNumber");
                    if (NULL != data)
                    {
                        xmldata->path_number = atoi(data);
                        xmlFree(data);
                    }
                    data = xmlGetProp(idable_node, "CombineMode");
                    if (NULL != data)
                    {
                        strncpy(xmldata->combinemode, data, strlen(data));
                        xmlFree(data);
                    }

                    xmlNodePtr name_path_node = idable_node->xmlChildrenNode;
                    /* while(NULL != name_path_node)
                    {
                        if (!xmlStrcmp(name_path_node->name, (const xmlChar *)"CustProductNamePath"))
                        {
                            data = xmlGetProp(idable_node, "RegistryPath");
                            if(NULL != data)
                            {
                                xmldata->path_number = data;
                                xmlFree(data);
                            }
                        }
                        name_path_node = name_path_node->next;
                    } */
                    if (!xmlStrcmp(name_path_node->name, (const xmlChar *)"CustProductNamePath"))
                    {
                        data = xmlGetProp(name_path_node, "RegistryPath");
                        if (NULL != data)
                        {
                            strncpy(xmldata->productname1_path, data, strlen(data));
                            xmlFree(data);
                        }
                    }
                    name_path_node = name_path_node->next;
                    if (!xmlStrcmp(name_path_node->name, (const xmlChar *)"CustProductNamePath"))
                    {
                        data = xmlGetProp(name_path_node, "RegistryPath");
                        if (NULL != data)
                        {
                            strncpy(xmldata->boardproduct_path, data, strlen(data));
                            xmlFree(data);
                        }
                    }
                }
                if (!xmlStrcmp(idable_node->name, (const xmlChar *)"MatchType"))
                {
                    data = xmlGetProp(idable_node, "SelectTypeName");
                    if (strlen(data))
                    {
                        strncpy(xmldata->selectType, data, strlen(data));
                    }
                    xmlFree(data);
                    CFG_LOG_DEBUG("SelectType:%s", xmldata->selectType);

                    xmlNodePtr type_node = idable_node->xmlChildrenNode;
                    while (NULL != type_node)
                    {
                        if (!xmlStrcmp(type_node->name, (const xmlChar *)"Type"))
                        {
                            data = xmlGetProp(type_node, "name");
                            if (0 == strcmp(xmldata->selectType, data))
                            {
                                strncpy(xmldata->selet_method.name, data, strlen(data));
                                xmlFree(data);
                                data = xmlGetProp(type_node, BAD_CAST "num");
                                if (NULL != data)
                                {
                                    xmldata->selet_method.num = atoi(data);
                                    xmlFree(data);
                                }
                                data = xmlGetProp(type_node, BAD_CAST "start");
                                if (NULL != data)
                                {
                                    xmldata->selet_method.start = atoi(data);
                                    xmlFree(data);
                                }
                                data = xmlGetProp(type_node, BAD_CAST "end");
                                if (NULL != data)
                                {
                                    xmldata->selet_method.end = atoi(data);
                                    xmlFree(data);
                                }
                                CFG_LOG_DEBUG("node_name:%s,num:%d,start:%d,end:%d", xmldata->selet_method.name, (int)xmldata->selet_method.num,
                                              (int)xmldata->selet_method.start, (int)xmldata->selet_method.end);
                            }
                        }
                        type_node = type_node->next;
                    }
                }
                if (!xmlStrcmp(idable_node->name, (const xmlChar *)"UniqueSkuIDToWwanDeviceConfigureIDMappingTable"))
                {
                    xmlNodePtr type_node = idable_node->xmlChildrenNode;
                    while (NULL != type_node)
                    {
                        if (!xmlStrcmp(type_node->name, (const xmlChar *)"UniqueSkuID"))
                        {
                            fibo_wwan_project_xml_t *wwan_project_list = NULL;
                            wwan_project_list = malloc(sizeof(fibo_wwan_project_xml_t));
                            if (NULL != wwan_project_list)
                            {
                                memset(wwan_project_list, 0, sizeof(fibo_wwan_project_xml_t));
                                data = xmlGetProp(type_node, BAD_CAST "WwanDeviceConfigID");
                                if (NULL != data)
                                {
                                    strncpy(wwan_project_list->wwanconfigid, data, strlen(data));
                                    xmlFree(data);
                                }
                                data = xmlGetProp(type_node, BAD_CAST "ProductID");
                                if (NULL != data)
                                {
                                    strncpy(wwan_project_list->projectid, data, strlen(data));
                                    xmlFree(data);
                                }
                                list_add_tail(&wwan_project_list->list, &xmldata->wwan_project_list);
                                // CFG_LOG_DEBUG("wwanconfigid:%s,projectid:%s", wwan_project_list->wwanconfigid, wwan_project_list->projectid);
                            }
                            else
                            {
                                CFG_LOG_ERROR("get memory error!");
                                xmlFreeDoc(doc);
                                return false;
                            }
                        }
                        type_node = type_node->next;
                    }
                }
                idable_node = idable_node->next;
            }
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"WwanDeviceConfigID_BlackList"))
        {
            xmlNodePtr type_node = node->xmlChildrenNode;
            while (NULL != type_node)
            {
                if (!xmlStrcmp(type_node->name, (const xmlChar *)"WwanDeviceConfigID"))
                {
                    fibo_wwancfg_disable_xml_t *wwancfg_disable_data = NULL;
                    wwancfg_disable_data = malloc(sizeof(fibo_wwancfg_disable_xml_t));
                    if (NULL != wwancfg_disable_data)
                    {
                        memset(wwancfg_disable_data, 0, sizeof(fibo_wwancfg_disable_xml_t));
                        data = xmlGetProp(type_node, BAD_CAST "WwanDeviceConfigIDValue");
                        if (NULL != data)
                        {
                            strncpy(wwancfg_disable_data->wwanconfigid, data, strlen(data));
                            xmlFree(data);
                        }
                        list_add_tail(&wwancfg_disable_data->list, &xmldata->wwancfg_disable_list);
                        // CFG_LOG_DEBUG("wwanconfigid:%s", wwancfg_disable_data->wwanconfigid);
                    }
                    else
                    {
                        CFG_LOG_ERROR("get memory error!");
                        xmlFreeDoc(doc);
                        return false;
                    }
                }
                type_node = type_node->next;
            }
        }
        node = node->next;
    }
    xmlFreeDoc(doc);
    return true;
}

bool fibo_parse_antenna_dynamic_data(char *filename, fibo_antenna_xml_t *xmldata)
{
    xmlDocPtr doc;
    xmlNodePtr node;
    bool ret = false;

    xmlChar *data = NULL;
    if (NULL == filename || NULL == xmldata)
    {
        CFG_LOG_ERROR("input para error ,exit");
        return false;
    }
    CFG_LOG_DEBUG("filename:%s", filename);
    doc = xmlParseFile(filename);
    if (NULL == doc)
    {
        CFG_LOG_ERROR("devicemode xml parse get file error!");
        return false;
    }
    node = xmlDocGetRootElement(doc);
    if (NULL == node)
    {
        CFG_LOG_ERROR("devicemode xml parse get root error!");
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(node->name, (const xmlChar *)"SarAntTableIndex"))
    {
        CFG_LOG_ERROR("devicemode xml parse node error!");
        xmlFreeDoc(doc);
        return false;
    }
    node = node->xmlChildrenNode;
    while (NULL != node)
    {
        if (!xmlStrcmp(node->name, (const xmlChar *)"WwanDeviceConfigIDList"))
        {
            xmlNodePtr wwanid_node = node->xmlChildrenNode;
            xmlNodePtr configid_node;
            while (NULL != wwanid_node)
            {
                if (!xmlStrcmp(wwanid_node->name, (const xmlChar *)"WwanDeviceConfigID"))
                {
                    data = xmlGetProp(wwanid_node, BAD_CAST "ID");
                    if (NULL != data)
                    {
                        data = xmlGetProp(wwanid_node, BAD_CAST "ID");
                        if (NULL != data)
                        {
                            if (0 == strcmp(xmldata->wwanconfig_id, data))
                            {
                                configid_node = wwanid_node;
                                CFG_LOG_DEBUG("find wwanconfig_id:%s", data);
                                xmlFree(data);
                                break;
                            }
                            else if (0 == strcmp(data, "default"))
                            {
                                configid_node = wwanid_node;
                                CFG_LOG_DEBUG("find default wwanconfig_id:%s,pc configid:%s", data, xmldata->wwanconfig_id);
                                xmlFree(data);
                            }
                        }
                    }
                }
                wwanid_node = wwanid_node->next;
            }

            xmlNodePtr switch_node = configid_node->xmlChildrenNode;
            while (NULL != switch_node)
            {
                if (!xmlStrcmp(switch_node->name, (const xmlChar *)"SwitchTable"))
                {
                    xmlNodePtr antenna_node = switch_node->xmlChildrenNode;
                    while (NULL != antenna_node)
                    {
                        if (!xmlStrcmp(antenna_node->name, (const xmlChar *)"AntTurnerTableIndex"))
                        {
                            xmlNodePtr index_node = antenna_node->xmlChildrenNode;
                            while (NULL != index_node)
                            {
                                if (!xmlStrcmp(index_node->name, (const xmlChar *)"Item"))
                                {
                                    data = xmlGetProp(index_node, BAD_CAST "DeviceMode");
                                    if (xmldata->device_mode == atoi(data))
                                    {
                                        xmlFree(data);
                                        data = xmlGetProp(index_node, BAD_CAST "Index");
                                        if (NULL != data)
                                        {
                                            xmldata->index = atoi(data);
                                            xmlFree(data);
                                            ret = true;
                                            goto END_PAESE;
                                        }
                                    }
                                }
                                index_node = index_node->next;
                            }
                        }
                        antenna_node = antenna_node->next;
                    }
                }
                switch_node = switch_node->next;
            }
        }
        node = node->next;
    }
END_PAESE:
    xmlFreeDoc(doc);
    return ret;
}

static char get_sar_index_from_xml(xmlNodePtr node)
{
    char index = 0;
    xmlChar *index_data = xmlGetProp(node, BAD_CAST "Index");
    if (NULL != index_data)
    {
        index = atoi(index_data);
        xmlFree(index_data);
    }
    return index;
}

static char get_device_mode_index(xmlNodePtr node)
{
    char index;
    xmlChar *index_data = xmlGetProp(node, BAD_CAST "DeviceMode");
    if (NULL != index_data)
    {
        index = atoi(index_data);
        xmlFree(index_data);
    }
    return index;
}

static char get_sensor1_index(xmlNodePtr node)
{
    char index;
    xmlChar *index_data = xmlGetProp(node, BAD_CAST "Sensor1");
    if (NULL != index_data)
    {
        index = atoi(index_data);
        xmlFree(index_data);
    }
    return index;
}

static char get_sensor2_index(xmlNodePtr node)
{
    char index;
    xmlChar *index_data = xmlGetProp(node, BAD_CAST "Sensor2");
    if (NULL != index_data)
    {
        index = atoi(index_data);
        xmlFree(index_data);
    }
    return index;
}

static char get_sensor3_index(xmlNodePtr node)
{
    char index;
    xmlChar *index_data = xmlGetProp(node, BAD_CAST "Sensor3");
    if (NULL != index_data)
    {
        index = atoi(index_data);
        xmlFree(index_data);
    }
    return index;
}

static bool sar_get_sar_type1_index(xmlNodePtr node, fibo_sar_xml1_t *xmldata)
{
    xmlNodePtr stand_node = node->xmlChildrenNode;
    xmlChar *data = NULL;
    while (NULL != stand_node)
    {
        if (!xmlStrcmp(stand_node->name, (const xmlChar *)"Standard"))
        {
            data = xmlGetProp(stand_node, BAD_CAST "Vaule");
            if (NULL != data)
            {
                if (0 == strcmp(xmldata->standard, data))
                {
                    xmlFree(data);
                    xmlNodePtr index_node = stand_node->xmlChildrenNode;
                    while (NULL != index_node)
                    {
                        if (!xmlStrcmp(index_node->name, (const xmlChar *)"Item"))
                        {
                            xmldata->index = get_sar_index_from_xml(index_node);
                            goto PARSE_END;
                        }
                        index_node = index_node->next;
                    }
                }
                xmlFree(data);
            }
        }
        stand_node = stand_node->next;
    }
PARSE_END:
    return true;
}

static bool sar_get_sar_type2_index(xmlNodePtr node, fibo_sar_xml2_t *xmldata)
{
    xmlNodePtr stand_node = node->xmlChildrenNode;
    xmlChar *data = NULL;
    bool found = false;
    while (NULL != stand_node)
    {
        if (!xmlStrcmp(stand_node->name, (const xmlChar *)"Standard"))
        {
            data = xmlGetProp(stand_node, BAD_CAST "Vaule");
            if (NULL != data)
            {
                if (0 == strcmp(xmldata->standard, data))
                {
                    xmlFree(data);
                    xmlNodePtr index_node = stand_node->xmlChildrenNode;
                    while (NULL != index_node)
                    {
                        if (!xmlStrcmp(index_node->name, (const xmlChar *)"Item"))
                        {
                            if (xmldata->device_mode == get_device_mode_index(index_node))
                            {
                                xmldata->index = get_sar_index_from_xml(index_node);
                                found = true;
                                goto PARSE_END;
                            }
                        }
                        index_node = index_node->next;
                    }
                }
                xmlFree(data);
            }
        }
        stand_node = stand_node->next;
    }
PARSE_END:
    if (found)
        return true;
    else
        return false;
}

static bool sar_get_sar_type3_index(xmlNodePtr node, fibo_sar_xml3_t *xmldata)
{
    xmlNodePtr stand_node = node->xmlChildrenNode;
    xmlChar *data = NULL;
    bool found = false;

    while (NULL != stand_node)
    {
        if (!xmlStrcmp(stand_node->name, (const xmlChar *)"Standard"))
        {
            data = xmlGetProp(stand_node, BAD_CAST "Vaule");
            if (NULL != data)
            {
                if (0 == strcmp(xmldata->standard, data))
                {
                    xmlFree(data);
                    xmlNodePtr index_node = stand_node->xmlChildrenNode;
                    while (NULL != index_node)
                    {
                        if (!xmlStrcmp(index_node->name, (const xmlChar *)"Item"))
                        {

                            if (xmldata->device_mode == get_device_mode_index(index_node))
                            {
                                if (xmldata->sensor1 == get_sensor1_index(index_node))
                                {
                                    xmldata->index = get_sar_index_from_xml(index_node);
                                    found = true;
                                    goto PARSE_END;
                                }
                            }
                        }
                        index_node = index_node->next;
                    }
                }
                xmlFree(data);
            }
        }
        stand_node = stand_node->next;
    }
PARSE_END:
    if (found)
        return true;
    else
        return false;
}

static bool sar_get_sar_type4_index(xmlNodePtr node, fibo_sar_xml4_t *xmldata)
{
    xmlNodePtr stand_node = node->xmlChildrenNode;
    xmlChar *data = NULL;
    bool found = false;
    while (NULL != stand_node)
    {
        if (!xmlStrcmp(stand_node->name, (const xmlChar *)"Standard"))
        {
            data = xmlGetProp(stand_node, BAD_CAST "Vaule");
            if (NULL != data)
            {

                if (0 == strcmp(xmldata->standard, data))
                {

                    xmlNodePtr index_node = stand_node->xmlChildrenNode;
                    while (NULL != index_node)
                    {
                        if (!xmlStrcmp(index_node->name, (const xmlChar *)"Item"))
                        {
                            if (xmldata->device_mode == get_device_mode_index(index_node))
                            {
                                if (xmldata->sensor1 == get_sensor1_index(index_node))
                                {
                                    if (xmldata->sensor2 == get_sensor2_index(index_node))
                                    {
                                        xmldata->index = get_sar_index_from_xml(index_node);
                                        found = true;
                                        goto PARSE_END;
                                    }
                                }
                            }
                        }
                        index_node = index_node->next;
                    }
                }
                xmlFree(data);
            }
        }
        stand_node = stand_node->next;
    }
PARSE_END:
    if (found)
        return true;
    else
        return false;
}

static bool sar_get_sar_type5_index(xmlNodePtr node, fibo_sar_xml5_t *xmldata)
{
    xmlNodePtr stand_node = node->xmlChildrenNode;
    xmlChar *data = NULL;
    bool found = false;

    while (NULL != stand_node)
    {

        if (!xmlStrcmp(stand_node->name, (const xmlChar *)"Standard"))
        {
            data = xmlGetProp(stand_node, BAD_CAST "Vaule");
            if (0 == strcmp(xmldata->standard, data))
            {
                xmlFree(data);
                xmlNodePtr index_node = stand_node->xmlChildrenNode;
                while (NULL != index_node)
                {
                    if (!xmlStrcmp(index_node->name, (const xmlChar *)"Item"))
                    {
                        if (xmldata->device_mode == get_device_mode_index(index_node))
                        {
                            if (xmldata->sensor1 == get_sensor1_index(index_node))
                            {
                                if (xmldata->sensor2 == get_sensor2_index(index_node))
                                {
                                    if (xmldata->sensor3 == get_sensor3_index(index_node))
                                    {
                                        xmldata->index = get_sar_index_from_xml(index_node);
                                        found = true;
                                        goto PARSE_END;
                                    }
                                }
                            }
                        }
                    }
                    index_node = index_node->next;
                }
            }
        }
        stand_node = stand_node->next;
    }
PARSE_END:
    if (found)
        return true;
    else
        return false;
}

bool fibo_parse_devicemode_index_data(char *filename, char *wwanconfig_id, char *map_type, void *xmldata)
{
    xmlDocPtr doc;
    xmlNodePtr node;
    bool ret = false;

    xmlChar *data = NULL;
    if (NULL == filename || NULL == map_type || NULL == xmldata)
    {
        CFG_LOG_ERROR("input para error ,exit");
        return false;
    }

    if (0 == strcmp(map_type, "MapType_1"))
    {
    }

    CFG_LOG_DEBUG("filename:%s", filename);
    doc = xmlParseFile(filename);
    if (NULL == doc)
    {
        CFG_LOG_ERROR("devicemode xml parse get file error!");
        return false;
    }
    node = xmlDocGetRootElement(doc);
    if (NULL == node)
    {
        CFG_LOG_ERROR("devicemode xml parse get root error!");
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(node->name, (const xmlChar *)"SarAntTableIndex"))
    {
        CFG_LOG_ERROR("devicemode xml parse node error!");
        xmlFreeDoc(doc);
        return false;
    }
    node = node->xmlChildrenNode;
    while (NULL != node)
    {
        if (!xmlStrcmp(node->name, (const xmlChar *)"WwanDeviceConfigIDList"))
        {
            xmlNodePtr wwanid_node = node->xmlChildrenNode;
            xmlNodePtr configid_node;
            while (NULL != wwanid_node)
            {
                if (!xmlStrcmp(wwanid_node->name, (const xmlChar *)"WwanDeviceConfigID"))
                {
                    data = xmlGetProp(wwanid_node, BAD_CAST "ID");
                    if (NULL != data)
                    {
                        if (0 == strcmp(wwanconfig_id, data))
                        {
                            configid_node = wwanid_node;
                            CFG_LOG_DEBUG("find wwanconfig_id:%s", data);
                            xmlFree(data);
                            break;
                        }
                        else if (0 == strcmp(data, "default"))
                        {
                            configid_node = wwanid_node;
                            CFG_LOG_DEBUG("find default wwanconfig_id:%s,pc configid:%s", data, wwanconfig_id);
                            xmlFree(data);
                        }
                    }
                }
                wwanid_node = wwanid_node->next;
            }
            xmlNodePtr switch_node = configid_node->xmlChildrenNode;
            while (NULL != switch_node)
            {
                if (!xmlStrcmp(switch_node->name, (const xmlChar *)"SwitchTable"))
                {
                    xmlNodePtr device_node = switch_node->xmlChildrenNode;
                    while (NULL != device_node)
                    {

                        if (!xmlStrcmp(device_node->name, (const xmlChar *)"SarTableIndex"))
                        {
                            xmlNodePtr sartype_node = device_node->xmlChildrenNode;
                            while (NULL != sartype_node)
                            {
                                if (!xmlStrcmp(sartype_node->name, (const xmlChar *)SAR_MAP_TYPE_1) && 0 == strcmp(map_type, SAR_MAP_TYPE_1))
                                {
                                    fibo_sar_xml1_t *xml_data = (fibo_sar_xml1_t *)xmldata;
                                    xmlNodePtr stand_node = sartype_node->xmlChildrenNode;
                                    ret = sar_get_sar_type1_index(sartype_node, xml_data);
                                    CFG_LOG_INFO("INDEX:%d", (int)xml_data->index);
                                    goto PARSE_END;
                                }
                                else if (!xmlStrcmp(sartype_node->name, (const xmlChar *)SAR_MAP_TYPE_2) && 0 == strcmp(map_type, SAR_MAP_TYPE_2))
                                {
                                    fibo_sar_xml2_t *xml_data = (fibo_sar_xml2_t *)xmldata;
                                    xmlNodePtr stand_node = sartype_node->xmlChildrenNode;
                                    ret = sar_get_sar_type2_index(sartype_node, xml_data);
                                    CFG_LOG_INFO("INDEX:%d", (int)xml_data->index);
                                }
                                else if (!xmlStrcmp(sartype_node->name, (const xmlChar *)SAR_MAP_TYPE_3) && 0 == strcmp(map_type, SAR_MAP_TYPE_3))
                                {
                                    fibo_sar_xml3_t *xml_data = (fibo_sar_xml3_t *)xmldata;
                                    xmlNodePtr stand_node = sartype_node->xmlChildrenNode;
                                    ret = sar_get_sar_type3_index(sartype_node, xml_data);
                                    CFG_LOG_INFO("INDEX:%d", (int)xml_data->index);
                                }
                                else if (!xmlStrcmp(sartype_node->name, (const xmlChar *)SAR_MAP_TYPE_4) && 0 == strcmp(map_type, SAR_MAP_TYPE_4))
                                {
                                    fibo_sar_xml4_t *xml_data = (fibo_sar_xml4_t *)xmldata;
                                    xmlNodePtr stand_node = sartype_node->xmlChildrenNode;
                                    ret = sar_get_sar_type4_index(sartype_node, xml_data);
                                    CFG_LOG_INFO("INDEX:%d", (int)xml_data->index);
                                }
                                else if (!xmlStrcmp(sartype_node->name, (const xmlChar *)SAR_MAP_TYPE_5) && 0 == strcmp(map_type, SAR_MAP_TYPE_5))
                                {
                                    fibo_sar_xml5_t *xml_data = (fibo_sar_xml5_t *)xmldata;
                                    xmlNodePtr stand_node = sartype_node->xmlChildrenNode;
                                    ret = sar_get_sar_type5_index(sartype_node, xml_data);
                                    CFG_LOG_INFO("INDEX:%d", (int)xml_data->index);
                                }
                                sartype_node = sartype_node->next;
                            }
                        }
                        device_node = device_node->next;
                    }
                }
                switch_node = switch_node->next;
            }
        }
        node = node->next;
    }
PARSE_END:
    xmlFreeDoc(doc);
    return ret;
}