package it.profesia.carbon.apimgt.gateway.handlers.utils;

import java.util.concurrent.TimeUnit;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CacheProviderWeModi{
	
	private static final Log log = LogFactory.getLog(CacheProviderWeModi.class);
	
	public static final String WEMODI_CACHE_NAME = "weModICache";
	public static final String WEMODI_CACHE_MANAGER = "WEMODI_CACHE_MANAGER";
	public static final long DEFAULT_TIMEOUT = 900;
	
	private static boolean enabledCache;
	private static long expiryTimeInSecondsCache;

	public static boolean isEnabledCache() {
		return CacheProviderWeModi.enabledCache;
	}

	public static void setEnabledCache(boolean enabledCache) {
		CacheProviderWeModi.enabledCache = enabledCache;
	}

	public static long getExpiryTimeInSecondsCache() {
		return CacheProviderWeModi.expiryTimeInSecondsCache;
	}

	public static void setExpiryTimeInSecondsCache(long expiryTimeInSecondsCache) {
		CacheProviderWeModi.expiryTimeInSecondsCache = expiryTimeInSecondsCache;
	}
	
	
    /**
     * @return weModI cache
     */
    public static Cache getWeModiCache() {
        return getCache(WEMODI_CACHE_MANAGER, WEMODI_CACHE_NAME);
    }
    
    /**
     * @return weModI cache
     */
    public static Cache getWeModiCache(String cacheName) {
        return getCache(WEMODI_CACHE_MANAGER, cacheName);
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
            if (cache.getName().equalsIgnoreCase(WEMODI_CACHE_NAME)) {
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
     * Create and return weModI cache
     */
    public static Cache createWeModiCache() {

    	long cacheExpiry = getExpiryTimeInSecondsCache();
        if (cacheExpiry != 0) {
            return getCache(WEMODI_CACHE_MANAGER,
            		WEMODI_CACHE_NAME, cacheExpiry,
            		cacheExpiry);
        } else {
            long defaultCacheTimeout = getDefaultCacheTimeout();
            return getCache(WEMODI_CACHE_MANAGER,
            		WEMODI_CACHE_NAME, defaultCacheTimeout, defaultCacheTimeout);
        }
    }


    /**
     * remove modi cache
     */
    public static void removeModiCache() {
        Caching.getCacheManager(WEMODI_CACHE_MANAGER).removeCache(CacheProviderWeModi.getWeModiCache()
        		.getName());
    }
    
    /**
     * Create and return weModI cache
     */
    public static Cache createWeModiCache(String cacheName) {

    	long cacheExpiry = getExpiryTimeInSecondsCache();
        if (cacheExpiry != 0) {
            return getCache(WEMODI_CACHE_MANAGER,
            		cacheName, cacheExpiry,
            		cacheExpiry);
        } else {
            long defaultCacheTimeout = getDefaultCacheTimeout();
            return getCache(WEMODI_CACHE_MANAGER,
            		cacheName, defaultCacheTimeout, defaultCacheTimeout);
        }
    }


    /**
     * remove modi cache
     */
    public static void removeModiCache(String cacheName) {
        Caching.getCacheManager(WEMODI_CACHE_MANAGER).removeCache(cacheName);
    }
    
    /**
     * @return default cache timeout value
     */
    private static long getDefaultCacheTimeout() {
        return DEFAULT_TIMEOUT;
    }
    
    public static void listAvailableCaches()
    {
    	Iterable<Cache<?, ?>> availableCaches = Caching.getCacheManager(WEMODI_CACHE_MANAGER).getCaches();
        for (Cache cache : availableCaches)
        	log.debug("Available cache name: " + cache.getName());
    }

}
