package it.profesia.wemodi.mediator;

import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.mediators.AbstractMediator;

/**
 * Mediatore per l'autenticazione degli endpoint ModI/PDND in fase di fruizione
 */
public class WeModIMediator extends AbstractMediator implements ManagedLifecycle {

	private String customParameters;

	@Override
	public boolean mediate(MessageContext synCtx) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void init(SynapseEnvironment se) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	public String getCustomParameters() {
		return customParameters;
	}

	public void setCustomParameters(String customParameters) {
		this.customParameters = customParameters;
	}

}
