#ifndef ICLOUD_H
#define ICLOUD_H

/**
 * @brief An iCloud context
 */
struct icloud;

struct icloud_cache_methods {

	/**
	 * @brief Initialization callback for cache
	 *
	 * @return The context to be used by the cache
	 */
	void* (*init)(void);

	/**
	 * @brief Write callback for cache
	 *
	 * @param[in] key Key for the cache entry
	 * @param[in] value Value oef the cache entry
	 * @param[in] context The context of the cache
	 *
	 * @return 0 on failure, otherwise, success
	 */
	int (*write)(const char* key, const char* value, void* context);

	/**
	 * @brief Read callback for cache
	 *
	 * @param[in] key Key for cache entry
	 * @param[in] context The context of the cache
	 *
	 * @return The value of the cache entry or NULL if empty
	 */
	const char* (*read) (const char* key, void* context);
	
	/**
	 * @brief Cleanup callback for cache
	 *
	 * @param[in] context The context of the cache
	 */
	void (*cleanup)(void* context);
};

/**
 * @brief Creates a text-based cache
 */
const struct icloud_cache_methods* text_file_cache();

/**
 * @brief Creates an in-memory only cache
 */
const struct icloud_cache_methods* in_memory_cache();

/**
 * @brief Creates a new icloud context
 *
 * Attemps to log in using the provided username and password
 *
 * @param[in] username iCloud username
 * @param[in] password iCloud password
 * @param[in] methods  iCloud cache methods
 * 
 * @return An icloud context
 */
struct icloud* icloud_new(const char* username,
						  const char* password, 
						  const struct icloud_cache_methods* methods);

/**
 * @brief Checks if two-factor is required.
 *
 * @return If two-factor authentication is required.
 */
int icloud_needs_2fa(struct icloud* icloud);

/**
 * @brief Submits two-factor authentication code
 *
 * @param[in] code Two-factor authentication code
 *
 * @return Whether two-factor was successful.
 */
int icloud_2fa(struct icloud* icloud, const char* code);

/**
 * @brief Frees an existing icloud context
 *
 * @param[in] context An iCloud context to free
 */
void icloud_free(struct icloud* icloud);

#endif /* ICLOUD_H */
