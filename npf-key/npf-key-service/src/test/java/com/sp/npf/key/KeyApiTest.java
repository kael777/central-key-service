package com.sp.npf.key;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class KeyApiTest {

    @Autowired
    private MockMvc mvc;

    private static MockHttpServletRequestBuilder from(MockHttpServletRequestBuilder b, String ip) {
        return b.with(request -> {
            request.setRemoteAddr(ip);
            return request;
        });
    }

    @Test
    void reconcileCreatesConfiguredKeys() throws Exception {
        mvc.perform(from(get("/keys"), "127.0.0.1").header("X-Client-Id", "npf-payment"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys['relay.callback'].current.value", notNullValue()))
                .andExpect(jsonPath("$.keys['relay.daifu.sign'].current.value", notNullValue()))
                .andExpect(jsonPath("$.refresh", notNullValue()));
    }

    @Test
    void etagReturns304WhenUnchanged() throws Exception {
        String etag = mvc.perform(from(get("/keys"), "127.0.0.1").header("X-Client-Id", "npf-payment"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getHeader("ETag");
        mvc.perform(from(get("/keys"), "127.0.0.1").header("X-Client-Id", "npf-payment").header("X-Key-Etag", etag))
                .andExpect(status().isNotModified());
    }

    @Test
    void rejectedWhenIpNotInRegistry() throws Exception {
        mvc.perform(from(get("/keys"), "10.1.1.1").header("X-Client-Id", "npf-payment"))
                .andExpect(status().isForbidden());
    }

    @Test
    void rejectedWhenKeyNotAllowed() throws Exception {
        mvc.perform(from(get("/keys/relay.daifu.sign"), "10.9.9.9").header("X-Client-Id", "other-client"))
                .andExpect(status().isForbidden());
    }

    @Test
    void rotateMovesCurrentToPrevious() throws Exception {
        mvc.perform(from(post("/admin/keys/relay.callback/rotate"), "127.0.0.1")
                        .param("reason", "test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CURRENT"));

        mvc.perform(from(get("/keys/relay.callback"), "127.0.0.1").header("X-Client-Id", "npf-payment"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys['relay.callback'].previous.value", notNullValue()));
    }

    @Test
    void secondRotationWithinIntervalRejected() throws Exception {
        mvc.perform(from(post("/admin/keys/relay.callback/rotate"), "127.0.0.1").param("reason", "test"))
                .andExpect(status().isOk());
        mvc.perform(from(post("/admin/keys/relay.callback/rotate"), "127.0.0.1").param("reason", "again"))
                .andExpect(status().isConflict());
    }

    @Test
    void adminRejectedFromNonLocalIp() throws Exception {
        mvc.perform(from(post("/admin/keys/relay.callback/rotate"), "10.1.2.3").param("reason", "x"))
                .andExpect(status().isForbidden());
    }

    @Test
    void importPartnerCreatesNewCurrent() throws Exception {
        mvc.perform(from(post("/admin/keys/game.ag.key/import"), "127.0.0.1")
                        .param("value", "partner-secret")
                        .param("remark", "AG")
                        .param("reason", "partner rotate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CURRENT"));
    }

    @Test
    void healthReportsDbAndKms() throws Exception {
        mvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"db\":\"UP\"")))
                .andExpect(header().exists("Content-Type"));
    }
}
