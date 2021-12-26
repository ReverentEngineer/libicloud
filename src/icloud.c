#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <uuid/uuid.h>

#include <icloud.h>

#include "config.h"

static const char* ACCOUNT_COUNTRY_HEADER = "X-Apple-ID-Account-Country: ";
static const char* SESSION_ID_HEADER = "X-Apple-ID-Session-Id: ";
static const char* SESSION_TOKEN_HEADER = "X-Apple-Session-Token: ";
static const char* TRUST_TOKEN_HEADER = "X-Apple-TwoSV-Trust-Token: ";
static const char* SCNT_HEADER = "scnt: ";

static const char* AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth";
static const char* HOME_ENDPOINT = "https://www.icloud.com";
static const char* SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1";

static const char* ACCEPT_ALL = "Accept: */*";
static const char* ACCEPT_JSON = "Accept: application/json";

static const char* get_cache() {
	static char cache_dir[255];
	if (getenv("LIBICLOUD_CACHE") != NULL) {
		snprintf(cache_dir, 255, "%s", getenv("LIBICLOUD_CACHE"));
	} else {
		snprintf(cache_dir, 255, "%s/.cache/libicloud/cache.txt", getenv("HOME"));
	}
	return cache_dir;
}


struct in_memory_cache_entry {
	char* key;
	char* value;
	struct in_memory_cache_entry* next;		
};

struct in_memory_cache {
	struct in_memory_cache_entry* root;
};

void* text_file_cache_init(void) {
	struct in_memory_cache* cache = malloc(sizeof(struct in_memory_cache));
	cache->root = NULL;
	assert(cache != NULL);
	FILE* fp = fopen(get_cache(), "r");
	if (fp) {
		char *key = NULL;
   		char *value = NULL;		
		while (fscanf(fp, "%ms=%ms\n", &key, &value) == 2) {
			struct in_memory_cache_entry* entry = malloc(sizeof(struct in_memory_cache_entry));
			assert(entry != NULL);
			entry->key = key;
			entry->value = value;
			entry->next = cache->root;
			cache->root = entry;
		}	
		fclose(fp);
	}
	return cache;
}

void text_file_cache_cleanup(void* context) {
	FILE* fp = fopen(get_cache(), "w");
	if (context != NULL) {
		struct in_memory_cache* cache = context;
		struct in_memory_cache_entry* it = cache->root;
		struct in_memory_cache_entry* tmp = cache->root;
		while (it != NULL) { 
			tmp = it;
			it = it->next;
			if (fp) {
				fprintf(fp, "%s=%s\n", tmp->key, tmp->value);
			}
			free(tmp->key);
			free(tmp->value);
			free(tmp);
		}
		free(context);
	}
	fclose(fp);
}

const char* in_memory_cache_read(const char* key, void* context) {
	struct in_memory_cache* cache = context;
	struct in_memory_cache_entry* it = cache->root;
	while (it != NULL) {
		if (strcmp(key, it->key) == 0) {
			return it->value;
		}
		it = it->next;
	}
	return NULL;
}

int in_memory_cache_write(const char* key, const char* value, void* context) {
	struct in_memory_cache* cache = context;
	struct in_memory_cache_entry* it = cache->root;
	while (it != NULL) {
		if (strcmp(key, it->key) == 0) {
			free(it->value);
			it->value = strdup(value);
			return 1;
		}
			
		it = it->next;
	}

	struct in_memory_cache_entry* entry = malloc(sizeof(struct in_memory_cache_entry));
	assert(entry != NULL);

	entry->key = strdup(key);
	entry->value = strdup(value);
	entry->next = cache->root;
	cache->root = entry;

	return 1;
}

void* in_memory_cache_init(void) {
	struct in_memory_cache* cache = malloc(sizeof(struct in_memory_cache));
	cache->root = NULL;
	assert(cache != NULL);
	return cache;
}

void in_memory_cache_cleanup(void* context) {
	if (context != NULL) {
		struct in_memory_cache* cache = context;
		struct in_memory_cache_entry* it = cache->root;
		struct in_memory_cache_entry* tmp = cache->root;
		while (it != NULL) { 
			tmp = it;
			it = it->next;
			free(tmp->key);
			free(tmp->value);
			free(tmp);
		}
	}
}

const struct icloud_cache_methods* text_file_cache() {
	static struct icloud_cache_methods cache = {
		.init = text_file_cache_init,
		.write = in_memory_cache_write,
		.read = in_memory_cache_read,
		.cleanup = text_file_cache_cleanup,
	};
	return &cache;
}


const struct icloud_cache_methods* in_memory_cache() {
	static struct icloud_cache_methods cache = {
		.init = text_file_cache_init,
		.write = in_memory_cache_write,
		.read = in_memory_cache_read,
		.cleanup = text_file_cache_cleanup,
	};
	return &cache;
}

static const char* GLOBAL_HEADERS[] = {
		"Origin: https://www.icloud.com", 
		"Referer: https://www.icloud.com/",
		NULL,
};

static const char* AUTH_HEADERS[] = {
		"Content-Type: application/json",
		"X-Apple-OAuth-Client-Id: d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
		"X-Apple-OAuth-Client-Type: firstPartyAuth",
		"X-Apple-OAuth-Redirect-URI: https://www.icloud.com",
		"X-Apple-OAuth-Require-Grant-Code: true",
		"X-Apple-OAuth-Response-Mode: web_message",
		"X-Apple-OAuth-Response-Type: code",
		"X-Apple-Widget-Key: d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
		NULL,
};
		
struct icloud {

	struct {
		const struct icloud_cache_methods* methods;
		void* context;
	} cache;
	

	CURL* curl;
	
	/** @brief CURL error buffer */
	char error_buffer[CURL_ERROR_SIZE];

	/** @brief Current headers to user **/
	char** headers;

	/** @brief Username **/
	char* username;

	/** @brief Password **/
	char* password;

	/** @brief Logged in **/ 
	int logged_in;

	/** @brief Needs two-factor authenticaton **/
	int needs_2fa;

};

#define cache_get(icloud, key) icloud->cache.methods->read(key, icloud->cache.context)
#define cache_set(icloud, key, value) icloud->cache.methods->write(key, value, icloud->cache.context)

#define extract_header_value(icloud, key, header, input, size) \
	if (memcmp(buffer, header, strlen(header)) == 0) { \
		char tmp[size - 2 + 1]; \
		memcpy(tmp, input, size - 2); \
		tmp[size - 2] = 0; \
		icloud->cache.methods->write(key, tmp, icloud->cache.context); \
	}

struct header_context {
	struct icloud* icloud;
	int response_code;
};

static const char* APPLE_RESPONSE_CODE_HEADER = "X-Apple-I-Rscd: ";

static void
parse_apple_response_code(struct header_context* context,
						  const char* buffer,
						  size_t size) {

	if (strlen(APPLE_RESPONSE_CODE_HEADER) + 2 < size &&
			memcmp(APPLE_RESPONSE_CODE_HEADER, 
			   buffer,
			   strlen(APPLE_RESPONSE_CODE_HEADER)) == 0) {
		sscanf(buffer + strlen(APPLE_RESPONSE_CODE_HEADER), "%d\r\n", &context->response_code);
	}

}

static size_t header_callback(char *buffer, 
							  size_t size,
				              size_t nitems,
							  void *userdata)
{
	struct header_context *context = (struct header_context *)userdata;
	size_t realsize = size * nitems;

	extract_header_value(context->icloud, "account_country", ACCOUNT_COUNTRY_HEADER, buffer, realsize)
	extract_header_value(context->icloud, "session_id", SESSION_ID_HEADER, buffer, realsize)
	extract_header_value(context->icloud, "session_token", SESSION_TOKEN_HEADER, buffer, realsize)
	extract_header_value(context->icloud, "trust_token", TRUST_TOKEN_HEADER, buffer, realsize)
	extract_header_value(context->icloud, "scnt", SCNT_HEADER, buffer, realsize)
	parse_apple_response_code(context, buffer, realsize);
	
	return nitems * size;
}


struct buffer {
	char *memory;
	size_t size;
};

static size_t
read_to_buffer(void *contents, size_t size, size_t nitems, void *userp)
{
	size_t realsize = size * nitems;
	struct buffer *mem = (struct buffer *)userp;
			 
	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		return 0;
	}
				 
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

static long
icloud_request(struct icloud* icloud,
		const char* url,
		const char** headers,
		const char* data,
		size_t data_size,
		json_object** response) {
	CURL* curl = icloud->curl;
	FILE* fdata = NULL;
	struct curl_slist *header_list = NULL;
	long http_code = 0;
	struct buffer response_data = {
		.memory = NULL,
		.size = 0
	};
	struct header_context header_context = {
		.icloud = icloud,
		.response_code = 0,
	};


	if (data != NULL && data_size > 0) {
		fdata = fmemopen((void*)data, data_size, "r");
	}

	icloud->error_buffer[0] = 0;
	if (curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, icloud->error_buffer) != CURLE_OK)
	  goto cleanup;

#ifdef CURL_VERBOSE
	if (curl_easy_setopt(curl, CURLOPT_VERBOSE, 1) != CURLE_OK)
		goto cleanup;
#endif

	if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK)
	  goto cleanup;

	for(const char** global_header = GLOBAL_HEADERS;
		*global_header != NULL;
		global_header++) {
		header_list = curl_slist_append(header_list, *global_header); 
	}

	if (headers != NULL) {
		for (; *headers != NULL; headers++) {
			header_list = curl_slist_append(header_list, *headers); 
		}

		if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list) != CURLE_OK)
			goto cleanup;
	}

	if (fdata) {
		if (curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK)
			goto cleanup;
	
		if (curl_easy_setopt(curl, CURLOPT_READDATA, fdata) != CURLE_OK)
			goto cleanup;
	}

	if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, read_to_buffer) != CURLE_OK)
			goto cleanup;

	if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data) != CURLE_OK)
			goto cleanup;

	if (curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback) != CURLE_OK)
			goto cleanup;

	if (curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_context) != CURLE_OK)
			goto cleanup;

 	if (curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "") != CURLE_OK)
			goto cleanup;

	if (curl_easy_perform(curl) != CURLE_OK)
		goto cleanup;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (header_context.response_code != 0) {
		http_code = header_context.response_code;
	}

	if (response != NULL && response_data.memory != NULL) {
		*response = json_tokener_parse(response_data.memory);	
	}
cleanup:
	if (response_data.memory != NULL) {
		free(response_data.memory);
	}
	if (curl)
		curl_easy_reset(curl);
	return http_code;
}


static int
authenticate_with_token(struct icloud* icloud) {
	const char* request_data = NULL;	
	static char login_url[255];
	const char** headers = NULL;

	snprintf(login_url, 255, "%s/accountLogin", SETUP_ENDPOINT);

	assert(cache_get(icloud, "account_country") != NULL);
	json_object* request = json_object_new_object();
	json_object_object_add(request,
		"accountCountryCode",
		json_object_new_string(cache_get(icloud, "account_country") + strlen(ACCOUNT_COUNTRY_HEADER)));

	assert(cache_get(icloud, "session_token") != NULL);
	json_object_object_add(request,
		"dsWebAuthToken",
		json_object_new_string(cache_get(icloud, "session_token") + strlen(SESSION_TOKEN_HEADER)));

	json_object_object_add(request,
		"extended_login",
		json_object_new_boolean(1));

	const char* trust_token = cache_get(icloud, "trust_token") != NULL ? cache_get(icloud, "trust_token") : "";
	json_object_object_add(request,
		"trustToken",
		json_object_new_string(trust_token + strlen(TRUST_TOKEN_HEADER)));

	if (request == NULL)
		goto cleanup;
	
	request_data = json_object_to_json_string_ext(request, JSON_C_TO_STRING_NOSLASHESCAPE);

	int header_count = 0;
	for (const char** current = AUTH_HEADERS; *current != NULL; current++) {
		headers = realloc(headers, (header_count + 2) * sizeof(const char*));
		headers[header_count] = *current;
		header_count++;
	}
		
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "client_id");
	header_count++;
	headers[header_count] = NULL;

	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = ACCEPT_ALL;
	header_count++;
	headers[header_count] = NULL;
	
	json_object* response = NULL;
	int response_code = icloud_request(icloud, login_url, headers, request_data, strlen(request_data), &response);

	if (response != NULL) {
		json_object* ds_info = NULL;
		if(json_object_object_get_ex(response, "dsInfo", &ds_info)) {
			json_object* hsa_required = NULL;
			if(json_object_object_get_ex(response, "hsaChallengeRequired", &hsa_required)) {
				icloud->needs_2fa = json_object_get_boolean(hsa_required);
			}
			
			if (icloud->needs_2fa) {
				if(json_object_object_get_ex(response, "hsaTrustedBrowser", &hsa_required)) {
					icloud->needs_2fa = !json_object_get_boolean(hsa_required);
				}
			}
		}
	}

cleanup:
	if (request)
		json_object_put(request);

	return response_code == 200 ? 1 : 0;
}


static void
authenticate_with_credentials(struct icloud* icloud) {

	const char* request_data = NULL;	
	static char login_url[255];
	const char** headers = NULL;

	snprintf(login_url, 255, "%s/signin?isRememberMeEnabled=true", AUTH_ENDPOINT);
	json_object* request = json_object_new_object();
	json_object_object_add(request,
		"accountName",
		json_object_new_string(icloud->username));

	json_object_object_add(request,
		"password",
		json_object_new_string(icloud->password));

	json_object_object_add(request,
		"rememberMe",
		json_object_new_boolean(1));

	json_object_object_add(request,
		"trustTokens",
		json_object_new_array());

	if (request == NULL)
		goto cleanup;
	
	request_data = json_object_to_json_string_ext(request, JSON_C_TO_STRING_NOSLASHESCAPE);

	int header_count = 0;
	for (const char** current = AUTH_HEADERS; *current != NULL; current++) {
		headers = realloc(headers, (header_count + 2) * sizeof(const char*));
		headers[header_count] = *current;
		header_count++;
	}
		
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "client_id");
	header_count++;
	headers[header_count] = NULL;
	
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = ACCEPT_ALL;
	header_count++;
	headers[header_count] = NULL;

	int response_code = icloud_request(icloud, login_url, headers, request_data, strlen(request_data), NULL);

	switch (response_code) {
		case 409:
			authenticate_with_token(icloud);
			break;
		default:
			break;
	}

cleanup:
	if (request)
		json_object_put(request);

}

struct icloud*
icloud_new(const char* username,
		   const char* password,
		   const struct icloud_cache_methods* methods) {
	struct icloud* icloud = malloc(sizeof(struct icloud));
	assert(icloud != NULL);

	icloud->cache.methods = methods;
	icloud->cache.context = icloud->cache.methods->init();

	icloud->curl = curl_easy_init();

	icloud->username = strdup(username);
	assert(icloud->username != NULL);

	icloud->password = strdup(password);
	assert(icloud->password != NULL);

	if (cache_get(icloud, "client_id") == NULL) {
		char tmp[255];
	
		sprintf(tmp, "X-Apple-OAuth-State: auth-");
		uuid_t uuid;
		uuid_generate_time(uuid);
		uuid_unparse(uuid, tmp + strlen(tmp));
		cache_set(icloud, "client_id", tmp);
	}

	if (!cache_get(icloud, "session_token")) {
	  authenticate_with_credentials(icloud);
	}
		
	authenticate_with_token(icloud);

	if (!icloud->needs_2fa && !icloud->logged_in) {
		icloud_free(icloud);
		icloud = NULL;
	}

	return icloud;
}

int
icloud_needs_2fa(struct icloud* icloud) {
	return icloud->needs_2fa;
}

static int 
authenticate_with_2fa(struct icloud* icloud, const char* code) {
	const char* request_data = NULL;	
	static char url[255];
	const char** headers = NULL;
	assert(code != NULL);

	snprintf(url, 255, "%s/verify/trusteddevice/securitycode", AUTH_ENDPOINT);
	

	json_object* securitycode = json_object_new_object();
	json_object_object_add(securitycode,
		"code",
		json_object_new_string(code));

	json_object* request = json_object_new_object();
	json_object_object_add(request,
		"securityCode",
		securitycode);
	
	request_data = json_object_to_json_string_ext(request, JSON_C_TO_STRING_NOSLASHESCAPE);

	int header_count = 0;
	for (const char** current = AUTH_HEADERS; *current != NULL; current++) {
		headers = realloc(headers, (header_count + 2) * sizeof(const char*));
		headers[header_count] = *current;
		header_count++;
	}
		
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "client_id");
	header_count++;
	headers[header_count] = NULL;
	
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "scnt");
	header_count++;
	headers[header_count] = NULL;

	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "session_id");
	header_count++;
	headers[header_count] = NULL;

	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = ACCEPT_JSON;
	header_count++;
	headers[header_count] = NULL;



	int response_code = icloud_request(icloud, url, headers, request_data, strlen(request_data), NULL);

	if (request)
		json_object_put(request);

	return response_code == 204 ? 1 : 0;
}

static int
trust_session(struct icloud* icloud) {
	static char url[255];
	const char** headers = NULL;
	snprintf(url, 255, "%s/2sv/trust", AUTH_ENDPOINT);

	int header_count = 0;
	for (const char** current = AUTH_HEADERS; *current != NULL; current++) {
		headers = realloc(headers, (header_count + 2) * sizeof(const char*));
		headers[header_count] = *current;
		header_count++;
	}
		
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "client_id");
	header_count++;
	headers[header_count] = NULL;
	
	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "scnt");
	header_count++;
	headers[header_count] = NULL;

	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = cache_get(icloud, "session_id");
	header_count++;
	headers[header_count] = NULL;

	headers = realloc(headers, (header_count + 2) * sizeof(const char*));
	headers[header_count] = ACCEPT_ALL;
	header_count++;
	headers[header_count] = NULL;

	int response_code = icloud_request(icloud, url, headers, NULL, 0, NULL);

	authenticate_with_token(icloud);

	return response_code == 204 ? 1 : 0;
}

int 
icloud_2fa(struct icloud* icloud, const char* code) {
	return authenticate_with_2fa(icloud, code) && \
			trust_session(icloud) && \
			authenticate_with_token(icloud);
}

void
icloud_free(struct icloud* icloud) {
	if (icloud) {
		icloud->cache.methods->cleanup(icloud->cache.context);
		if (icloud->curl) {
			curl_easy_cleanup(icloud->curl);
		}
		if (icloud->username) {
			free(icloud->username);
		}
		if (icloud->password) {
			free(icloud->password);
		}
		free(icloud);
	}
}
