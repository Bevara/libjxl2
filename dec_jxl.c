#include <gpac/filters.h>

#include "jxl/decode.h"

typedef struct
{
    Bool want_hdr;

    GF_FilterPid *ipid, *opid;

    Bool is_playing;
    u32 src_timescale;
    u32 codec_id;
    u32 ofmt;
} GF_JXLDecCtx;

static GF_Err jxldec_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{
    const GF_PropertyValue *prop;
    GF_JXLDecCtx *ctx = (GF_JXLDecCtx *)gf_filter_get_udta(filter);

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

    prop = gf_filter_pid_get_property(pid, GF_PROP_PID_CODECID);
    if (!prop)
        return GF_NOT_SUPPORTED;
    ctx->ipid = pid;

    if (!ctx->opid)
    {
        ctx->opid = gf_filter_pid_new(filter);
    }

    // copy properties at init or reconfig
    gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
    gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(GF_CODECID_RAW));
    
    if (!ctx->ofmt) {
        ctx->ofmt = GF_PIXEL_RGBA;
        gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(GF_PIXEL_RGBA));
    }else{
        gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(ctx->ofmt));
    }

    return GF_OK;
}

static GF_Err jxldec_reconfigure_output(GF_Filter *filter, GF_FilterPid *pid)
{
	const GF_PropertyValue *p;
	GF_JXLDecCtx *ctx = gf_filter_get_udta(filter);
	if (ctx->opid != pid) return GF_BAD_PARAM;

	p = gf_filter_pid_caps_query(pid, GF_PROP_PID_PIXFMT);
	if (p) ctx->ofmt = p->value.uint;
	return jxldec_configure_pid(filter, ctx->ipid, GF_FALSE);
}

static GF_Err jxldec_process(GF_Filter *filter)
{

    GF_Err e;
    GF_FilterPacket *pck;
    u8 *data;
    u32 size;
    GF_JXLDecCtx *ctx = (GF_JXLDecCtx *)gf_filter_get_udta(filter);

    pck = gf_filter_pid_get_packet(ctx->ipid);
    if (!pck)
    {
        if (gf_filter_pid_is_eos(ctx->ipid))
        {
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
    JxlDecoder *decoder = JxlDecoderCreate(0);

    JxlDecoderStatus status = JxlDecoderSubscribeEvents(
        decoder, JXL_DEC_COLOR_ENCODING | JXL_DEC_FULL_IMAGE);
    if (JXL_DEC_SUCCESS != status)
    {
        GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSubscribeEvents failed\n"));
        return GF_OUT_OF_MEM;
    }

    status = JxlDecoderSetProgressiveDetail(decoder, kPasses);
    if (JXL_DEC_SUCCESS != status)
    {
        GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSubscribeEvents failed\n"));
        return GF_OUT_OF_MEM;
    }

    status = JxlDecoderSetInput(decoder, data, size);
    if (JXL_DEC_SUCCESS != status)
    {
        GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetInput failed\n"));
        return GF_NOT_SUPPORTED;
    }

    while (1)
    {
        GF_FilterPacket *dst_pck;
        u8 *output;

        status = JxlDecoderProcessInput(decoder);
        if (JXL_DEC_SUCCESS == status)
        {
            JxlDecoderReleaseInput(decoder);
            JxlDecoderDestroy(decoder);
            return GF_OK; // ¯\_(ツ)_/¯
        }
        else if (JXL_DEC_NEED_MORE_INPUT == status)
        {
            JxlDecoderReleaseInput(decoder);
            JxlDecoderDestroy(decoder);
            return GF_OK;
        }
        else if (JXL_DEC_FULL_IMAGE == status)
        {
            gf_filter_pck_merge_properties(pck, dst_pck);
            gf_filter_pck_set_dependency_flags(dst_pck, 0);
            gf_filter_pck_send(dst_pck);

            JxlDecoderReleaseInput(decoder);
            gf_filter_pid_drop_packet(ctx->ipid);
            JxlDecoderDestroy(decoder);
            return GF_OK; // final image is ready
        }
        else if (JXL_DEC_NEED_IMAGE_OUT_BUFFER == status)
        {

            status =
                JxlDecoderImageOutBufferSize(decoder, &format, &pixels_size);
            if (status != JXL_DEC_SUCCESS)
            {
                JxlDecoderReleaseInput(decoder);
                JxlDecoderDestroy(decoder);
                GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderImageOutBufferSize failed\n"));
                return GF_NOT_SUPPORTED;
            }

            dst_pck = gf_filter_pck_new_alloc(ctx->opid, pixels_size, &output);
            if (!dst_pck)
                return GF_OUT_OF_MEM;

            status = JxlDecoderSetImageOutBuffer(decoder, &format, output,
                                                 pixels_size);
            if (status != JXL_DEC_SUCCESS)
            {
                gf_filter_pck_discard(dst_pck);
                JxlDecoderReleaseInput(decoder);
                GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetImageOutBuffer failed\n"));
                return GF_NOT_SUPPORTED;
            }
        }
        else if (JXL_DEC_COLOR_ENCODING == status)
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
            status = JxlDecoderSetPreferredColorProfile(decoder, &color_encoding);
            if (status != JXL_DEC_SUCCESS)
            {
                JxlDecoderReleaseInput(decoder);
                JxlDecoderDestroy(decoder);
                GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetPreferredColorProfile failed\n"));
                return GF_NOT_SUPPORTED;
            }
        }
        else
        {
            JxlDecoderReleaseInput(decoder);
            JxlDecoderDestroy(decoder);
            GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: Unexpected decoder status\n"));
            return GF_NOT_SUPPORTED;
        }
    }

    JxlDecoderReleaseInput(decoder);
    JxlDecoderDestroy(decoder);
    return GF_OK;
}

#define OFFS(_n)	#_n, offsetof(GF_JXLDecCtx, _n)
static GF_FilterArgs EVGSArgs[] =
{
	{ OFFS(ofmt), "pixel format for output image. When not set, input format is used", GF_PROP_PIXFMT, "none", NULL, 0},

	{0}
};

static const GF_FilterCapability JXLDecCaps[] =
    {
        CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
        CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_CODECID, GF_4CC('J', 'X', 'L', ' ')),
        CAP_BOOL(GF_CAPS_INPUT_EXCLUDED, GF_PROP_PID_UNFRAMED, GF_TRUE),
        CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
        CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_CODECID_RAW),
};

#define OFFS(_n) #_n, offsetof(GF_JXLDecCtx, _n)

static const GF_FilterArgs JXLDecArgs[] =
    {
        {OFFS(want_hdr), "Output in wide dynamic range instead of standard dynamic range instead", GF_PROP_BOOL, "false", NULL, GF_FS_ARG_HINT_ADVANCED},
        {0}};

GF_FilterRegister JXLDecoderRegister = {
    .name = "jxldec",
    GF_FS_SET_DESCRIPTION("JXL decoder")
        GF_FS_SET_HELP("This filter decodes JXL images.")
            .private_size = sizeof(GF_JXLDecCtx),
    SETCAPS(JXLDecCaps),
    .configure_pid = jxldec_configure_pid,
    .reconfigure_output = jxldec_reconfigure_output,
    .process = jxldec_process,
};

const GF_FilterRegister * EMSCRIPTEN_KEEPALIVE dynCall_jxldec_register(GF_FilterSession *session)
{
    return &JXLDecoderRegister;
}

void abort() {
  _Exit(1);
}