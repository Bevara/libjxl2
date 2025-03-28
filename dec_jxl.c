/*
 *            GPAC - Multimedia Framework C SDK
 *
 *            Authors: Jean Le Feuvre
 *            Copyright (c) Telecom ParisTech 2000-2022
 *                    All rights reserved
 *
 *  This file is part of GPAC / image (jpg/png/bmp/j2k) reframer filter
 *
 *  GPAC is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  GPAC is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

 #include <gpac/filters.h>
 #include <gpac/bitstream.h>
 #include "jxl/decode.h"
 
 typedef struct
 {
     Bool want_hdr;
     
     // only one input pid declared
     GF_FilterPid *ipid;
     // only one output pid declared
     GF_FilterPid *opid;
     u32 ofmt;
     JxlDecoder *decoder;
     GF_FilterPacket *dst_pck;
 } GF_JXLDecCtx;
 
 static GF_Err decjxl_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
 {
     GF_JXLDecCtx *ctx = gf_filter_get_udta(filter);
 
     if (is_remove)
     {
         if (ctx->opid)
         {
             gf_filter_pid_remove(ctx->opid);
             ctx->opid = NULL;
         }
         ctx->ipid = NULL;
         return GF_OK;
     }
 
     if (!gf_filter_pid_check_caps(pid))
         return GF_NOT_SUPPORTED;
     
     ctx->ipid = pid;
     if (!ctx->ofmt) {
         ctx->ofmt = GF_PIXEL_RGBA;
     }
     ctx->dst_pck = NULL;
     return GF_OK;
 }
 
 static GF_Err decjxl_reconfigure_output(GF_Filter *filter, GF_FilterPid *pid)
 {
     const GF_PropertyValue *p;
     GF_JXLDecCtx *ctx = gf_filter_get_udta(filter);
     if (ctx->opid != pid) return GF_BAD_PARAM;
 
     p = gf_filter_pid_caps_query(pid, GF_PROP_PID_PIXFMT);
     if (p) ctx->ofmt = p->value.uint;
     if (ctx->opid){
         gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(ctx->ofmt));
     }
 
     return GF_OK;
 }
 
 
 static
 GF_Err decjxl_initialize(GF_Filter *filter)
 {
     GF_JXLDecCtx *ctx = gf_filter_get_udta(filter);
     ctx->decoder = JxlDecoderCreate(0);
     return GF_OK;
 }
 
 static void decjxl_finalize(GF_Filter *filter)
 {
     GF_JXLDecCtx *ctx = gf_filter_get_udta(filter);
     JxlDecoderDestroy(ctx->decoder);
 }
 
 static GF_Err decjxl_process(GF_Filter *filter)
 {
     GF_JXLDecCtx *ctx = gf_filter_get_udta(filter);
     GF_FilterPacket *pck;
     GF_Err e;
     u8 *data;
     u32 size, w = 0, h = 0, pf = 0;
 
     pck = gf_filter_pid_get_packet(ctx->ipid);
     if (!pck)
     {
         if (gf_filter_pid_is_eos(ctx->ipid))
         {
             if (ctx->opid)
                 gf_filter_pid_set_eos(ctx->opid);
             return GF_EOS;
         }
         return GF_OK;
     }
     data = (u8 *)gf_filter_pck_get_data(pck, &size);
 
     if (!data)
     {
         gf_filter_pid_drop_packet(ctx->ipid);
         return GF_IO_ERR;
     }
     
     JxlPixelFormat format;
     size_t pixels_size;
 
     JxlDataType storageFormat = ctx->want_hdr ? JXL_TYPE_UINT16 : JXL_TYPE_UINT8;
     switch (ctx->ofmt)
     {
     case GF_PIXEL_RGBA:
         format.num_channels = 4;
         break;
     case GF_PIXEL_RGB:
         format.num_channels = 3;
         break;
     default:
         format.num_channels = 3;
         break;
     }
     
     format.data_type = storageFormat;
     format.endianness = JXL_NATIVE_ENDIAN;
     format.align = 0;
     
     JxlDecoderStatus status = JxlDecoderSetInput(ctx->decoder, data, size);
     if (JXL_DEC_SUCCESS != status)
     {
         GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetInput failed\n"));
         return GF_NOT_SUPPORTED;
     }
     
     status = JxlDecoderSubscribeEvents(
         ctx->decoder, JXL_DEC_COLOR_ENCODING | JXL_DEC_FULL_IMAGE |JXL_DEC_BASIC_INFO);
   
     
     while (1)
     {
 
         u8 *output;
         
         status = JxlDecoderProcessInput(ctx->decoder);
         if (JXL_DEC_SUCCESS == status)
         {
             JxlDecoderReleaseInput(ctx->decoder);
             gf_filter_pid_drop_packet(ctx->ipid);
             return GF_OK; // ¯\_(ツ)_/¯
         } else if (JXL_DEC_NEED_MORE_INPUT == status)
         {
             JxlDecoderReleaseInput(ctx->decoder);
             gf_filter_pid_drop_packet(ctx->ipid);
             return GF_OK;
         }else if (JXL_DEC_FULL_IMAGE == status)
         {
             if (ctx->dst_pck){
                 gf_filter_pck_merge_properties(pck, ctx->dst_pck);
                 gf_filter_pck_set_dependency_flags(ctx->dst_pck, 0);
                 gf_filter_pck_send(ctx->dst_pck);
             }
 
             JxlDecoderReleaseInput(ctx->decoder);
             gf_filter_pid_drop_packet(ctx->ipid);
             return GF_OK; // final image is ready
         }else if (JXL_DEC_NEED_IMAGE_OUT_BUFFER == status)
         {
 
             status =
                 JxlDecoderImageOutBufferSize(ctx->decoder, &format, &pixels_size);
             if (status != JXL_DEC_SUCCESS)
             {
                 JxlDecoderReleaseInput(ctx->decoder);
                 GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderImageOutBufferSize failed\n"));
                 return GF_NOT_SUPPORTED;
             }
 
             ctx->dst_pck = gf_filter_pck_new_alloc(ctx->opid, pixels_size, &output);
             if (!ctx->dst_pck)
                 return GF_OUT_OF_MEM;
 
             status = JxlDecoderSetImageOutBuffer(ctx->decoder, &format, output,
                                                  pixels_size);
             if (status != JXL_DEC_SUCCESS)
             {
                 gf_filter_pck_discard(ctx->dst_pck);
                 JxlDecoderReleaseInput(ctx->decoder);
                 GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetImageOutBuffer failed\n"));
                 return GF_NOT_SUPPORTED;
             }
         }else if (JXL_DEC_COLOR_ENCODING == status)
         {
             JxlColorEncoding color_encoding;
             color_encoding.color_space = JXL_COLOR_SPACE_RGB;
             color_encoding.white_point = JXL_WHITE_POINT_D65;
             color_encoding.primaries =
                 ctx->want_hdr ? JXL_PRIMARIES_2100 : JXL_PRIMARIES_SRGB;
             color_encoding.transfer_function = ctx->want_hdr
                                                    ? JXL_TRANSFER_FUNCTION_PQ
                                                    : JXL_TRANSFER_FUNCTION_SRGB;
             color_encoding.rendering_intent = JXL_RENDERING_INTENT_PERCEPTUAL;
             status = JxlDecoderSetPreferredColorProfile(ctx->decoder, &color_encoding);
             if (status != JXL_DEC_SUCCESS)
             {
                 JxlDecoderReleaseInput(ctx->decoder);
                 GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetPreferredColorProfile failed\n"));
                 return GF_NOT_SUPPORTED;
             }
         }else if (JXL_DEC_BASIC_INFO == status)
         {
             JxlBasicInfo info;
             status = JxlDecoderGetBasicInfo(ctx->decoder, &info);
             if (status != JXL_DEC_SUCCESS)
             {
                 JxlDecoderReleaseInput(ctx->decoder);
                 GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderGetBasicInfo failed\n"));
                 return GF_CORRUPTED_DATA;
             }
 
             ctx->opid = gf_filter_pid_new(filter);
             if (!ctx->opid)
             {
                 gf_filter_pid_drop_packet(ctx->ipid);
                 return GF_SERVICE_ERROR;
             }
 
             pf = (info.num_extra_channels == 1) && (info.num_color_channels == 3) ? GF_PIXEL_RGBA : (info.num_extra_channels == 1) && (info.num_color_channels == 1) ? GF_PIXEL_GREYSCALE
                                                                                                 : (info.num_color_channels == 3)                                     ? GF_PIXEL_RGB
                                                                                                 : (info.num_color_channels == 1)                                     ? GF_PIXEL_GREYSCALE
                                                                                                                                                                      : 0;
 
             w = info.xsize;
             h = info.ysize;
 
             // we don't have input reconfig for now
             gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
             gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_VISUAL));
             gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(GF_CODECID_RAW));
             gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(ctx->ofmt));
             if (w)
                 gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(info.xsize));
             if (h)
                 gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(info.ysize));
 
             gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_NB_FRAMES, &PROP_UINT(1));
             gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PLAYBACK_MODE, &PROP_UINT(GF_PLAYBACK_MODE_FASTFORWARD));
         }
     }
 
     return e;
 }
 
 static const char *decjxl_probe_data(const u8 *data, u32 size, GF_FilterProbeScore *score)
 {
     if ((data[0] == 0xFF) && (data[1] == 0x0A))
     {
         *score = GF_FPROBE_SUPPORTED;
         return "image/jxl";
     }
 
     GF_BitStream *bs = gf_bs_new(data, size, GF_BITSTREAM_READ);
     u32 bsize = gf_bs_read_u32(bs);
     u32 btype = gf_bs_read_u32(bs);
     if ((bsize == 12) && (btype == GF_4CC('J', 'X', 'L', ' ')))
     {
         btype = gf_bs_read_u32(bs);
         if (btype == 0x0D0A870A)
         {
             *score = GF_FPROBE_FORCE;
             gf_bs_del(bs);
             return "image/jxl";
         }
     }
     gf_bs_del(bs);
     return NULL;
 }
 
 static const GF_FilterCapability JXLDecCaps[] =
     {
         CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_FILE),
         CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_FILE_EXT, "jxl"),
         CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_MIME, "image/jxl"),
         CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
         CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_CODECID_RAW),
 };
 
 #define OFFS(_n) #_n, offsetof(GF_JXLDecCtx, _n)
 static const GF_FilterArgs JXLDecArgs[] =
     {
         {OFFS(want_hdr), "Output in wide dynamic range instead of standard dynamic range instead", GF_PROP_BOOL, "false", NULL, GF_FS_ARG_HINT_ADVANCED},
         {0}};
 
 
 GF_FilterRegister JXLDecoderRegister = {
     .name = "jxldec_opt",
     GF_FS_SET_DESCRIPTION("JXL optimized decoder")
         GF_FS_SET_HELP("This filter decodes JXL images using a single filter.\n")
             .private_size = sizeof(GF_JXLDecCtx),
     .args = JXLDecArgs,
     SETCAPS(JXLDecCaps),
     .initialize = decjxl_initialize,
     .finalize = decjxl_finalize,
     .configure_pid = decjxl_configure_pid,
     .reconfigure_output = decjxl_reconfigure_output,
     .probe_data = decjxl_probe_data,
     .process = decjxl_process};
 
 
 const GF_FilterRegister * jxldec_register(GF_FilterSession *session)
 {
     return &JXLDecoderRegister;
 }
 