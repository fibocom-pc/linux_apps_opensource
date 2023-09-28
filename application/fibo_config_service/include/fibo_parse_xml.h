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
 * @file fibo_parse_xml.h
 * @author ziqi.zhao@fibocom.com (zhaoziqi)
 * @brief 
 * @version 1.0
 * @date 2023-09-23
 * 
 * 
 **/

#ifndef __FIBO_XML_PARSE_H__
#define __FIBO_XML_PARSE_H__
#include <stdio.h>
#include <stdbool.h>
#include "fibo_list.h"

#define FIBO_SKU_PATH_LEN 256
#define FIBO_WWANCONFIGID_PATH_LEN 256
#define FIBO_SELECT_TYPE 32
#define FIBO_REGION_VER 32
#define FIBO_MCC_LEN 16
#define FIBO_REGULATORY_LEN 8
#define FIBO_COUNTRY_LEN 32
#define FIBO_COMBINE_LEN 16


#define SAR_MAP_TYPE_1 "MapType_1"
#define SAR_MAP_TYPE_2 "MapType_2"
#define SAR_MAP_TYPE_3 "MapType_3"
#define SAR_MAP_TYPE_4 "MapType_4"
#define SAR_MAP_TYPE_5 "MapType_5"


typedef enum parse_xml_type_t
{
    FIBO_PARSE_XML_ESIM = 0,
    FIBO_PARSE_XML_REGION_MAP,
    FIBO_PARSE_XML_DEVMODE_SELECT_INDEX,
    SAR_PASE_XML_TYPE_UNKNOWN,
} parse_xml_type;

struct type_method
{
    char name[FIBO_SELECT_TYPE];
    char num;
    char start;
    char end;
};

typedef struct fibo_sku_black_xml_s
{
    struct list_head list;
    char sku[16];
} fibo_sku_black_xml_t;

typedef struct fibo_mcc_black_xml_s
{
    struct list_head list;
    char mcc[16];
} fibo_mcc_black_xml_t;

typedef struct esim_xml_parse_rule_t
{
    bool esim_enable;
    char SystemSKU_path[FIBO_SKU_PATH_LEN];
    char SelectType[FIBO_SELECT_TYPE];
    struct type_method selet_method;
} esim_xml_parse_rule_t;

typedef struct esim_xml_parse_s
{
    esim_xml_parse_rule_t xml_parse_rule;
    /* fibo_sku_black_xml_t SKU_black_list;
    fibo_mcc_black_xml_t mccmnc_black_list; */
    struct list_head sku_black_list;
    struct list_head mcc_black_list;

} esim_disable_parse_t;

typedef struct fibo_wwan_project_xml_s
{
    struct list_head list;
    char wwanconfigid[64];
    char projectid[64];
} fibo_wwan_project_xml_t;

typedef struct fibo_wwancfg_disable_xml_s
{
    struct list_head list;
    char wwanconfigid[32];
} fibo_wwancfg_disable_xml_t;

typedef struct fibo_antenna_xml_s
{
    char *wwanconfig_id;
    char device_mode;
    char index;
} fibo_antenna_xml_t;


typedef struct fibo_sar_xml1_s
{
    char *standard;
    char index;
} fibo_sar_xml1_t;

typedef struct fibo_sar_xml2_s
{
    char *standard;
    char device_mode;
    char index;
} fibo_sar_xml2_t;

typedef struct fibo_sar_xml3_s
{
    char *standard;
    char device_mode;
    char sensor1;
    char index;
} fibo_sar_xml3_t;

typedef struct fibo_sar_xml4_s
{
    char *standard;
    char device_mode;
    char sensor1;
    char sensor2;
    char index;
} fibo_sar_xml4_t;

typedef struct fibo_sar_xml5_s
{
    char *standard;
    char device_mode;
    char sensor1;
    char sensor2;
    char sensor3;
    char index;
} fibo_sar_xml5_t;

typedef struct device_config_index_list_s
{
    char *wwanconfig_id;
    char *map_type;
    char *standard;
    union
    {
        struct list_head map_type1_list;
        struct list_head map_type2_list;
        struct list_head map_type3_list;
        struct list_head map_type4_list;
        struct list_head map_type5_list;
    } sar_xml_map;

} device_sar_antenna_index_list_t;

typedef struct devicemode_index_xml_parse_s
{
    bool select_index_enable;
    char path_number;
    char combinemode[FIBO_COMBINE_LEN];
    char productname1_path[FIBO_SKU_PATH_LEN];
    char boardproduct_path[FIBO_WWANCONFIGID_PATH_LEN];
    char selectType[FIBO_SELECT_TYPE];
    struct type_method selet_method;
    struct list_head wwan_project_list;
    struct list_head wwancfg_disable_list;
    /* fibo_wwan_project_xml_t project_xml;
    fibo_wwancfg_disable_xml_t wwancfg_disable_list; */

} devicemode_static_xml_parse_t;

typedef struct fibo_select_rule_xml_s
{
    struct list_head list;
    char mcc[FIBO_MCC_LEN];
    char regulatory[FIBO_REGULATORY_LEN];
    char country[FIBO_COUNTRY_LEN];
} fibo_select_rule_xml_t;

typedef struct fibo_sar_custom_s
{
    struct list_head list;
    char regulatory[FIBO_REGULATORY_LEN];
    char sar_type[1];
    char db_offset_enable[1];
} fibo_sar_custom_t;

typedef struct region_map_xml_parse_s
{
    char region_ver[FIBO_REGION_VER];
    /* fibo_select_rule_xml_t select_rule;
    fibo_sar_custom_t custom_rule; */
    struct list_head select_rule_list;
    struct list_head sar_custom_list;
} region_map_xml_parse_t;


// int fibo_parse_xml(void);
// int xml_write(void);
// int xml_read(void);

bool fibo_parse_esim_xml_data(char *filename, esim_xml_parse_rule_t *xmldata,
                             struct list_head *list_sku, struct list_head *list_mcc);
bool fibo_parse_region_mapping_data(char *filename, char *parse_ver, char *version, struct list_head *select_rule_list,
                                   struct list_head *sar_custom_list);
bool fibo_parse_devicemode_static_data(char *filename, devicemode_static_xml_parse_t *xmldata);

bool fibo_parse_devicemode_index_data(char *filename, char *wwanconfig_id, char *map_type, void *xmldata);

bool fibo_parse_antenna_dynamic_data(char *filename, fibo_antenna_xml_t *xmldata);
#endif