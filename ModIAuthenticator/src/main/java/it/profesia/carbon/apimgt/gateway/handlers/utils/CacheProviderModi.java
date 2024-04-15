package it.profesia.carbon.apimgt.gateway.handlers.utils;

import java.util.concurrent.TimeUnit;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CacheProviderModi{
	
	private static final Log log = LogFactory.getLog(CacheProviderModi.class);
	
	public static final String MODI_CACHE_NAME = "modiCache";
	public static final String MODI_CACHE_MANAGER = "MODI_CACHE_MANAGER";
	public static final long DEFAULT_TIMEOUT = 900;
	
	private static boolean enabledCache;
	private static long expiryTimeInSecondsCache;

	public static boolean isEnabledCache() {
		return CacheProviderModi.enabledCache;
	}

	public static void setEnabledCache(boolean enabledCache) {
		CacheProviderModi.enabledCache = enabledCache;
	}

	public static long getExpiryTimeInSecondsCache() {
		return CacheProviderModi.expiryTimeInSecondsCache;
	}

	public static void setExpiryTimeInSecondsCache(long expiryTimeInSecondsCache) {
		CacheProviderModi.expiryTimeInSecondsCache = expiryTimeInSecondsCache;
	}
	
	
    /**
     * @return Modi cache
     */
    public static Cache getModiCache() {
        return getCache(MODI_CACHE_MANAGER, MODI_CACHE_NAME);
    }
    
    /**
     * Create the Cache object from the given parameters
     *
     * @param cacheManagerName - Name of the Cache Manager
     * @param cacheName        - Name of the Cache
     * @param modifiedExp      - Value of the MODIFIED Expiry Type
     * @param accessExp        - Value of the ACCESSED Expiry Type
     * @return - The cache object
     */
    private synchronized static Cache getCache(final String cacheManagerName, final String cacheName, final long modifiedExp,
                                              final long accessExp) {

        Iterable<Cache<?, ?>> availableCaches = Caching.getCacheManager(cacheManagerName).getCaches();
        for (Cache cache : availableCaches) {
            if (cache.getName().equalsIgnoreCase(MODI_CACHE_NAME)) {
                return Caching.getCacheManager(cacheManagerName).getCache(cacheName);
            }
        }
        return Caching.getCacheManager(
                cacheManagerName).createCacheBuilder(cacheName).
                setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS,
                        modifiedExp)).
                setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS,
                        accessExp)).setStoreByValue(false).build();
    }



    /**
     * Get the Cache object using cacheManagerName & cacheName
     *
     * @param cacheManagerName - Name of the Cache Manager
     * @param cacheName        - Name of the Cache
     * @return existing cache
     */
    private static Cache getCache(final String cacheManagerName, final String cacheName) {

        return Caching.getCacheManager(cacheManagerName).getCache(cacheName);
    }


    /**
     * Create and return modi cache
     */
    public static Cache createModiCache() {

    	long cacheExpiry = getExpiryTimeInSecondsCache();
        if (cacheExpiry != 0) {
            return getCache(MODI_CACHE_MANAGER,
            		MODI_CACHE_NAME, cacheExpiry,
            		cacheExpiry);
        } else {
            long defaultCacheTimeout = getDefaultCacheTimeout();
            return getCache(MODI_CACHE_MANAGER,
            		MODI_CACHE_NAME, defaultCacheTimeout, defaultCacheTimeout);
        }
    }


    /**
     * remove modi cache
     */
    public static void removeModiCache() {
        Caching.getCacheManager(MODI_CACHE_MANAGER).removeCache(CacheProviderModi.getModiCache()
        		.getName());
    }
    
    /**
     * @return default cache timeout value
     */
    private static long getDefaultCacheTimeout() {
        return DEFAULT_TIMEOUT;
    }

}
