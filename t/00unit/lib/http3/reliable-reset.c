/* Included after h3-fixture.c by the server unit translation unit: the lifecycle of request streams that are reset, by
 * RESET_STREAM or by RESET_STREAM_AT, as the end of the stream (see `handle_buffered_input`). */
#if !H2O_USE_LIBUV
/* fills `bytes` with an unknown (reserved) frame, which the receiver skips */
static void rr_unknown_frame(uint8_t *bytes, size_t len)
{
    assert(3 <= len && len - 3 < 16384);
    bytes[0] = 0x21;
    bytes[1] = 0x40 | (uint8_t)((len - 3) >> 8);
    bytes[2] = (uint8_t)(len - 3);
    memset(bytes + 3, 0xff, len - 3);
}

static void rr_check_credit(struct rr_fixture *f)
{
    uint64_t consumed, shifted;
    quicly_get_max_data(f->server->h3.super.quic, NULL, NULL, &consumed, &shifted);
    ok(consumed == shifted);
}

/* the connection-level credit charged and not returned */
static uint64_t rr_credit_held(struct rr_fixture *f)
{
    uint64_t consumed, shifted;
    quicly_get_max_data(f->server->h3.super.quic, NULL, NULL, &consumed, &shifted);
    return consumed - shifted;
}

/* A transfer completed by RESET_STREAM_AT, by the reset or by a STREAM frame arriving after it, is not the end of a request, whose
 * body has no content-length; the request is not processed, the body being incomplete, and is cancelled. */
static void rr_test_body_completed_by_reset(struct rr_fixture *f, int reset_first)
{
    static const uint8_t body[] = {0, 4, 'b', 'o', 'd', 'y'};
    unsigned calls = rr_handler_calls;
    quicly_stream_t *qs = rr_write(f, 0, rr_get, sizeof(rr_get));
    quicly_stream_id_t id = qs->stream_id;
    struct rr_client_stream *cs = qs->data;
    struct rr_packets held, reset;
    rr_collect(f->client, &held);
    rr_deliver(f, 1, &held);
    quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
    assert(server_qs != NULL);
    struct st_h2o_http3_server_stream_t *s = server_qs->data;
    ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK);
    assert(quicly_streambuf_egress_write(qs, body, sizeof(body)) == 0);
    rr_collect(f->client, &held);
    ok(held.count != 0);
    if (!reset_first)
        rr_deliver(f, 1, &held);
    rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, sizeof(rr_get) + sizeof(body));
    rr_collect(f->client, &reset);
    ok(reset.count != 0);
    rr_deliver(f, 1, &reset);
    if (reset_first) {
        ok(!quicly_recvstate_transfer_complete(&server_qs->recvstate));
        rr_deliver(f, 1, &held);
    }
    ok(quicly_recvstate_transfer_complete(&server_qs->recvstate) &&
       server_qs->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
    ok(rr_handler_calls == calls);
    rr_check_credit(f);
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(rr_handler_calls == calls);
    ok(cs->super.ingress.off == 0); /* no response */
    rr_check_credit(f);
}

/* The client's QPACK encoder stream, opened on the first insert of each connection, and the number of entries inserted. */
static struct {
    struct rr_fixture *f;
    quicly_stream_t *qs;
    uint64_t insert_count;
} rr_qpack_encoder;

/* Writes a request that references the next entry of the dynamic table, which is not inserted until `rr_qpack_insert` is called.
 * Its field section is that of rr_get, but with :authority taken from the dynamic table. */
static size_t rr_qpack_blocked_request(struct rr_fixture *f, uint8_t *buf)
{
    uint64_t max_entries = f->server->h3.qpack.ctx->decoder_table_capacity / 32,
             required_insert_count = rr_qpack_encoder.f == f ? rr_qpack_encoder.insert_count + 1 : 1;
    uint8_t *p = buf + 2;
    *p = 0;
    p = h2o_hpack_encode_int(p, required_insert_count % (2 * max_entries) + 1, 8);
    *p++ = 0x00; /* Delta Base of zero */
    *p++ = 0xd1; /* :method: GET */
    *p++ = 0xd7; /* :scheme: https */
    *p++ = 0xc1; /* :path: / */
    *p++ = 0x80; /* :authority, the dynamic table entry of relative index 0 */
    buf[0] = 1;  /* HEADERS */
    buf[1] = (uint8_t)(p - buf - 2);
    return p - buf;
}

/* Inserts `:authority: localhost` into the dynamic table of the server's QPACK decoder, and delivers the instruction. */
static void rr_qpack_insert(struct rr_fixture *f)
{
    static const uint8_t insert[] = {0xc0 /* static name reference, :authority */, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'};
    if (rr_qpack_encoder.f != f) {
        uint8_t open[1 + H2O_HPACK_ENCODE_INT_MAX_LENGTH] = {0x02 /* QPACK encoder stream */, 0x20}, *p = open + 1;
        p = h2o_hpack_encode_int(p, 64, 5); /* Set Dynamic Table Capacity */
        rr_qpack_encoder.f = f;
        rr_qpack_encoder.qs = rr_write(f, 1, open, p - open);
        rr_qpack_encoder.insert_count = 0;
    }
    assert(quicly_streambuf_egress_write(rr_qpack_encoder.qs, insert, sizeof(insert)) == 0);
    ++rr_qpack_encoder.insert_count;
    struct rr_packets batch;
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
}

/* Returns whether the server's QPACK decoder stream carries a Stream Cancellation of `stream_id`. */
static int rr_qpack_cancelled(struct rr_fixture *f, quicly_stream_id_t stream_id)
{
    for (struct rr_client_stream *s = f->streams; s != NULL; s = s->next) {
        if (!(quicly_stream_is_unidirectional(s->id) && !quicly_stream_is_client_initiated(s->id)) || s->super.ingress.off == 0 ||
            s->super.ingress.base[0] != 0x03 /* QPACK decoder stream */)
            continue;
        const uint8_t *src = s->super.ingress.base + 1, *end = s->super.ingress.base + s->super.ingress.off;
        while (src != end) {
            unsigned prefix_bits = (*src & 0x80) != 0 ? 7 : 6; /* Section Acknowledgment, or the others */
            int is_cancel = (*src & 0xc0) == 0x40;
            int64_t value = h2o_hpack_decode_int(&src, end, prefix_bits);
            assert(value >= 0);
            if (is_cancel && value == stream_id)
                return 1;
        }
    }
    return 0;
}

static void rr_test_response_and_qpack(struct rr_fixture *f, int mode)
{
    /* An already-final early error response is preserved by reset_only_if_open; a QPACK-blocked request must instead be
     * cancelled and removed from its delayed list, which happens once the headers are decoded. Both cases have
     * buffered/previously-consumed data before the reset. */
    uint8_t qpack_blocked[32];
    size_t qpack_blocked_len = rr_qpack_blocked_request(f, qpack_blocked);
    int blocked = mode != 0;
    unsigned calls = rr_handler_calls;
    uint8_t early_error[sizeof(rr_get) + 3];
    memcpy(early_error, rr_get, sizeof(rr_get));
    early_error[1] += 3;
    memcpy(early_error + sizeof(rr_get),
           "\x54\x01"
           "1",
           3); /* content-length: 1 */
    f->conf.max_request_entity_size = 0;
    quicly_stream_t *qs = rr_write(f, 0, blocked ? qpack_blocked : early_error, blocked ? qpack_blocked_len : sizeof(early_error));
    quicly_stream_id_t id = qs->stream_id;
    struct rr_packets held, reset;
    rr_collect(f->client, &held);
    rr_deliver(f, 1, &held);
    quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
    assert(server_qs != NULL);
    struct st_h2o_http3_server_stream_t *s = server_qs->data;
    if (blocked) {
        ok(s->qpack_blocked_ref != 0 && f->server->num_qpack_blocked == 1);
    } else {
        ok(s->req.res.status == 413);
        ok(!quicly_sendstate_is_open(&server_qs->sendstate));
    }
    if (mode == 2) {
        /* Use an open, QPACK-blocked response: for the final early error response, whose FIN is in flight, quicly would also call
         * on_send_stop (#715). A real STOP_SENDING must move this request to CLOSE_WAIT before its first receive-reset callback. */
        quicly_request_stop(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        rr_collect(f->client, &reset);
        rr_deliver(f, 1, &reset);
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT && s->req_disposed);
    }
    /* bytes are sent beyond the Reliable Size; quicly drops them once the reset has been received (#550 8a22a76d) */
    uint8_t tail[64];
    rr_unknown_frame(tail, sizeof(tail));
    assert(quicly_streambuf_egress_write(qs, tail, sizeof(tail)) == 0);
    rr_collect(f->client, &held);
    size_t request_len = blocked ? qpack_blocked_len : sizeof(early_error);
    rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, request_len + 8);
    rr_collect(f->client, &reset);
    assert(reset.count != 0);
    rr_deliver(f, 1, &reset);
    /* the reset is not reported before the bytes below the Reliable Size have been received */
    ok(server_qs->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
    ok(server_qs->recvstate.eos == request_len + 8);
    ok(s->state == (mode == 2 ? H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT
                    : blocked ? H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS
                              : H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY));
    /* the reset charges the final size and returns at once the credit of the bytes above the Reliable Size */
    ok(rr_credit_held(f) == request_len + 8 - server_qs->recvstate.data_off);
    rr_deliver(f, 1, &held);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == server_qs);
    ok(quicly_recvstate_transfer_complete(&server_qs->recvstate) && server_qs->recvstate.eos == request_len + 8);
    if (mode == 1) {
        /* the reset is handled once the headers are decoded, which waits for the insert they reference */
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS);
        ok(s->qpack_blocked_ref != 0 && f->server->num_qpack_blocked == 1);
        rr_qpack_insert(f);
    }
    ok(s->qpack_blocked_ref == 0 && f->server->num_qpack_blocked == 0);
    ok(!h2o_linklist_is_linked(&s->link));
    ok(rr_handler_calls == calls);
    ok(s->state == (mode != 0 ? H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT : H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY));
    handle_buffered_input(s, 0); /* deferred processing is also inert */
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(rr_handler_calls == calls);
    if (blocked)
        ok(rr_qpack_cancelled(f, id));
    /* the credit of the bytes left unprocessed in CLOSE_WAIT is returned when the stream is destroyed */
    rr_check_credit(f);
    rr_check_get(f);
}

/* quicly #715: STOP_SENDING resets the send side of a request stream even once the response is final, unless its FIN has been
 * acknowledged, and then calls on_send_stop, which must not reset it again. Mode 0 sends STOP_SENDING along with the request, mode
 * 1 after the response, whose flight is lost, and mode 2 before the response, the STOP_SENDING arriving after the acknowledgement
 * of the FIN. The reset, sent through h2o's scheduler, carries the peer's error code and goes out once. */
static void rr_test_stop_after_response(struct rr_fixture *f, int mode)
{
    quicly_stats_t before, after;
    assert(quicly_get_stats(f->server->h3.super.quic, &before) == 0);
    quicly_stream_t *qs = rr_write(f, 0, rr_get, sizeof(rr_get));
    struct rr_client_stream *cs = qs->data;
    quicly_stream_id_t id = qs->stream_id;
    assert(quicly_streambuf_egress_shutdown(qs) == 0);
    if (mode == 0)
        quicly_request_stop(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    struct rr_packets batch, stop;
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
    h2o_timer_unlink(&f->server->timeout);
    run_delayed(&f->server->timeout);
    if (mode != 0) {
        quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
        assert(server_qs != NULL);
        uint64_t final_size = server_qs->sendstate.final_size;
        ok(quicly_sendstate_eos_type(&server_qs->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_FIN);
        rr_collect(f->server->h3.super.quic, &batch);
        ok(server_qs->sendstate.size_inflight == final_size);
        quicly_request_stop(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
        rr_collect(f->client, &stop);
        if (mode == 1) {
            rr_deliver(f, 1, &stop);
            server_qs = quicly_get_stream(f->server->h3.super.quic, id);
            ok(server_qs != NULL && quicly_sendstate_eos_type(&server_qs->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET &&
               server_qs->sendstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED) &&
               server_qs->sendstate.final_size == final_size);
        } else {
            struct rr_packets ack;
            rr_deliver(f, 0, &batch);
            ok(cs->fin);
            rr_clock += 30; /* past the delay of the acknowledgement */
            rr_collect(f->client, &ack);
            rr_deliver(f, 1, &ack);
            server_qs = quicly_get_stream(f->server->h3.super.quic, id);
            ok(server_qs == NULL || quicly_sendstate_transfer_complete(&server_qs->sendstate));
            rr_deliver(f, 1, &stop);
        }
    }
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(cs->destroyed);
    assert(quicly_get_stats(f->server->h3.super.quic, &after) == 0);
    uint64_t resets = after.num_frames_sent.reset_stream - before.num_frames_sent.reset_stream;
    printf("# stop after response (mode %d): %" PRIu64 " RESET_STREAM sent\n", mode, resets);
    ok(resets == (mode == 2 ? 0 : 1));
    ok(cs->reset_err == (mode == 2 ? 0 : H2O_HTTP3_ERROR_REQUEST_CANCELLED));
    ok(mode != 2 || cs->fin);
    rr_check_credit(f);
}

/* A request blocked on QPACK and reset by a plain RESET_STREAM is cancelled once its headers are decoded, as one ending with a FIN
 * would be, and the server sends a Stream Cancellation. */
static void rr_test_qpack_blocked_plain_reset(void)
{
    struct rr_fixture *f = rr_setup();
    const uint8_t settings[] = {0, 4, 0};
    rr_write(f, 1, settings, sizeof(settings));
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    unsigned calls = rr_handler_calls;
    uint8_t request[32];
    quicly_stream_t *qs = rr_write(f, 0, request, rr_qpack_blocked_request(f, request));
    quicly_stream_id_t id = qs->stream_id;
    struct rr_packets batch;
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
    quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
    assert(server_qs != NULL);
    struct st_h2o_http3_server_stream_t *s = server_qs->data;
    ok(s->qpack_blocked_ref != 0 && f->server->num_qpack_blocked == 1);
    quicly_reset_stream(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    rr_collect(f->client, &batch);
    rr_deliver(f, 1, &batch);
    ok(quicly_recvstate_transfer_complete(&server_qs->recvstate));
    /* still blocked, until the insert arrives */
    ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS);
    ok(s->qpack_blocked_ref != 0 && f->server->num_qpack_blocked == 1);
    rr_qpack_insert(f);
    ok(s->qpack_blocked_ref == 0 && f->server->num_qpack_blocked == 0);
    ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
    ok(rr_handler_calls == calls);
    ok(rr_qpack_cancelled(f, id));
    rr_check_get(f);
    rr_dispose(f);
}

static void test_h3_reliable_reset(void)
{
    rr_test_qpack_blocked_plain_reset();

    struct rr_fixture *f = rr_setup();
    const uint8_t settings[] = {0, 4, 0};
    rr_write(f, 1, settings, sizeof(settings));
    for (unsigned i = 0; i != 8; ++i)
        rr_step(f);
    ok(h2o_http3_has_received_settings(&f->server->h3));

    /* Many reliably reset requests exceed the initial connection window. Deliver reset before all data, then the held
     * bytes, without delivering STOP to the sender first. A credit leak would block later requests. The reset charges the final
     * size and returns at once the credit of the bytes above the Reliable Size, which are dropped when they arrive; it is
     * reported once the bytes below it have arrived, and the rest of the credit is returned when the stream is destroyed. On odd
     * iterations the Reliable Size equals the final size. */
    for (unsigned i = 0; i != 8; ++i) {
        uint8_t bytes[2048];
        rr_unknown_frame(bytes, sizeof(bytes)); /* incomplete unless all bytes are delivered */
        quicly_stream_t *qs = rr_write(f, 0, bytes, sizeof(bytes));
        quicly_stream_id_t id = qs->stream_id;
        struct rr_packets held, reset;
        rr_collect(f->client, &held);
        ok(held.count != 0);
        uint64_t reliable_size = i % 2 != 0 ? sizeof(bytes) : 16;
        rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, reliable_size);
        rr_collect(f->client, &reset);
        ok(reset.count != 0);
        rr_deliver(f, 1, &reset);
        quicly_stream_t *server_qs = quicly_get_stream(f->server->h3.super.quic, id);
        ok(server_qs != NULL);
        assert(server_qs != NULL);
        struct st_h2o_http3_server_stream_t *s = server_qs->data;
        ok(server_qs->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
        ok(server_qs->recvstate.eos == reliable_size);
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS && !s->req_disposed);
        ok(rr_credit_held(f) == reliable_size);
        rr_deliver(f, 1, &held);
        ok(quicly_get_stream(f->server->h3.super.quic, id) == server_qs);
        ok(s->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT && s->req_disposed);
        ok(quicly_recvstate_transfer_complete(&server_qs->recvstate) && server_qs->recvstate.eos == reliable_size);
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
        rr_check_credit(f);
    }
    rr_test_body_completed_by_reset(f, 0);
    rr_test_body_completed_by_reset(f, 1);
    rr_test_response_and_qpack(f, 0);
    rr_test_response_and_qpack(f, 1);
    rr_test_response_and_qpack(f, 2);
    rr_test_stop_after_response(f, 0);
    rr_test_stop_after_response(f, 1);
    rr_test_stop_after_response(f, 2);
    rr_check_get(f);
    rr_dispose(f);

    /* Minimal and all nonminimal type widths, with reset before type, after partial type, after a sparse suffix, and after
     * known type. Critical-stream reset must not be forgotten; unknown extensions must leave this H3 connection usable. */
    const uint64_t types[] = {0, 2, 3, 0x21};
    for (size_t t = 0; t != PTLS_ELEMENTSOF(types); ++t) {
        for (unsigned variant = 0; variant != 16; ++variant) {
            size_t width = (size_t)1 << (variant / 4);
            unsigned partial = variant % 4;
            if (width == 1 && partial == 1)
                continue; /* a one-byte type has no partial encoding */
            printf("# uni type=%" PRIu64 " width=%zu ordering=%u (0=reset-first,1=fragmented,2=sparse,3=known)\n", types[t], width,
                   partial);
            f = rr_setup();
            uint8_t bytes[2048] = {0};
            bytes[0] = width == 8 ? 0xc0 : width == 4 ? 0x80 : width == 2 ? 0x40 : 0;
            bytes[width - 1] |= (uint8_t)types[t];
            /* The bytes following the type are delivered and processed before the reset is reported; use valid input: SETTINGS
             * then an unknown frame, Set Dynamic Table Capacity (0) and Stream Cancellation (0) instructions, or opaque bytes. */
            switch (types[t]) {
            case 0:
                bytes[width] = 4;
                bytes[width + 1] = 0;
                rr_unknown_frame(bytes + width + 2, sizeof(bytes) - width - 2);
                break;
            case 2:
                memset(bytes + width, 0x20, sizeof(bytes) - width);
                break;
            case 3:
                memset(bytes + width, 0x40, sizeof(bytes) - width);
                break;
            default:
                memset(bytes + width, 0xff, sizeof(bytes) - width);
                break;
            }
            size_t initial = partial == 1 ? (width == 8 ? 3 : width - 1) : partial == 3 ? width : sizeof(bytes);
            quicly_stream_t *qs = rr_write(f, 1, bytes, initial);
            quicly_stream_id_t id = qs->stream_id;
            struct rr_packets held, reset;
            if (partial == 1 || partial == 3) {
                rr_collect(f->client, &held);
                rr_deliver(f, 1, &held);
                quicly_stream_t *incoming = quicly_get_stream(f->server->h3.super.quic, id);
                assert(incoming != NULL);
                /* on_receive's offset is relative to data_off, not an absolute wire offset. An incomplete type must
                 * consume NOTHING, otherwise the next callback will interpret its continuation as a new type. */
                printf("# after initial %zu type bytes: data_off=%" PRIu64 " available=%zu\n", initial,
                       incoming->recvstate.data_off, quicly_recvstate_bytes_available(&incoming->recvstate));
                ok(incoming->recvstate.data_off == (partial == 1 ? 0 : width));
                assert(quicly_streambuf_egress_write(qs, bytes + initial, sizeof(bytes) - initial) == 0);
            }
            rr_collect(f->client, &held);
            ok(held.count != 0);
            if (partial == 2) {
                /* Deliver only the high-offset packet first, forcing a sparse pre-reset buffer. */
                assert(held.count >= 2);
                struct rr_packets suffix = {.count = 1};
                suffix.packets[0] = held.packets[held.count - 1];
                rr_deliver(f, 1, &suffix);
                --held.count;
            }
            uint64_t reliable_size = partial == 3 ? width + 8 : width;
            rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, reliable_size);
            rr_collect(f->client, &reset);
            ok(reset.count != 0);
            rr_deliver(f, 1, &reset);
            /* the bytes below the Reliable Size are still to be received, so the reset is not reported yet (even for a known
             * critical stream); the sparse suffix, above the Reliable Size, is dropped */
            ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
            quicly_stream_t *incoming = quicly_get_stream(f->server->h3.super.quic, id);
            assert(incoming != NULL);
            ok(incoming->recvstate.app_error_code == QUICLY_ERROR_GET_ERROR_CODE(H2O_HTTP3_ERROR_REQUEST_CANCELLED));
            ok(incoming->recvstate.eos == reliable_size);
            /* the credit of the sparse suffix stays tied to the memory holding it until the stream is destroyed */
            ok(rr_credit_held(f) == (partial == 2 ? sizeof(bytes) : reliable_size) - incoming->recvstate.data_off);
            rr_deliver(f, 1, &held);
            if (types[t] == 0x21) {
                ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
                rr_check_credit(f);
                ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
                if (quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED) {
                    rr_write(f, 1, settings, sizeof(settings));
                    for (unsigned j = 0; j != 8; ++j)
                        rr_step(f);
                }
                rr_check_get(f);
            } else {
                ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CLOSING);
                ok(quicly_get_close_reason(f->server->h3.super.quic, NULL, NULL, NULL) == H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
                /* Exercise the actual close emission / stream destruction and the peer's wire-observed error. */
                rr_collect(f->server->h3.super.quic, &reset);
                ok(quicly_num_streams(f->server->h3.super.quic) == 0);
                rr_deliver(f, 0, &reset);
                ok(quicly_get_state(f->client) == QUICLY_STATE_DRAINING);
                ok(quicly_get_close_reason(f->client, NULL, NULL, NULL) == H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
                ok(quicly_num_streams(f->client) == 0);
            }
            rr_dispose(f);
        }
    }

    /* An unknown type reset before any byte arrives with a Reliable Size equal to the final size: the final size is charged at
     * the reset, and the credit returned as the bytes are discarded and once the transfer completes. */
    f = rr_setup();
    {
        uint8_t bytes[2048];
        memset(bytes, 0xff, sizeof(bytes));
        bytes[0] = 0x21;
        quicly_stream_t *qs = rr_write(f, 1, bytes, sizeof(bytes));
        quicly_stream_id_t id = qs->stream_id;
        struct rr_packets held, reset;
        rr_collect(f->client, &held);
        ok(held.count != 0);
        rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, sizeof(bytes));
        rr_collect(f->client, &reset);
        ok(reset.count != 0);
        rr_deliver(f, 1, &reset);
        ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
        ok(rr_credit_held(f) == sizeof(bytes));
        rr_deliver(f, 1, &held);
        rr_check_credit(f);
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        ok(quicly_get_stream(f->server->h3.super.quic, id) == NULL);
        rr_write(f, 1, settings, sizeof(settings));
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        rr_check_get(f);
    }
    rr_dispose(f);

    /* A control stream whose bytes have all been consumed, then reset with a Reliable Size covering them: the reset completes the
     * transfer without delivering new bytes, and still closes the connection, the stream being critical. */
    f = rr_setup();
    {
        quicly_stream_t *qs = rr_write(f, 1, settings, sizeof(settings));
        for (unsigned j = 0; j != 8; ++j)
            rr_step(f);
        ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CONNECTED);
        rr_reset_at(qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED, sizeof(settings));
        struct rr_packets reset;
        rr_collect(f->client, &reset);
        ok(reset.count != 0);
        rr_deliver(f, 1, &reset);
        ok(quicly_get_state(f->server->h3.super.quic) == QUICLY_STATE_CLOSING);
        ok(quicly_get_close_reason(f->server->h3.super.quic, NULL, NULL, NULL) == H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM);
    }
    rr_dispose(f);
}
#else
static void test_h3_reliable_reset(void)
{
    printf("# reliable reset transport fixture requires the native event loop\n");
}
#endif