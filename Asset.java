package tus_crypto;

import java.io.Serializable; 

class Asset implements Serializable {
	private static final long serialVersionUID = -6186645918087808772L;
	// Declare Asset Variables, declare as private to improve encapsulation.
	private String assetType = "";
	private String assetLocation = "";
	private int assetValue = 0;
	
	// Declare Asset Constructor
	Asset(String assetType, String assetLocation, int assetValue) {
		setAssetType(assetType);
		setAssetLocation(assetLocation);
		setAssetValue(assetValue);		
	}
	
	// Add toString override method to output asset details.
	public String toString() {
		String assetDetails = ("Type: "+ getAssetType()+". Location: "+getAssetLocation()+". Value: "+getAssetValue());
		return assetDetails;
	}

	// Create Getters and Setters for each Asset variable
	// to remove requirement to directly reference the variables
	// and improve encapsulation.
	String getAssetType() {
		return assetType;
	}
	void setAssetType(String assetType) {
		this.assetType = assetType;
	}
	String getAssetLocation() {
		return assetLocation;
	}
	void setAssetLocation(String assetLocation) {
		this.assetLocation = assetLocation;
	}
	int getAssetValue() {
		return assetValue;
	}
	void setAssetValue(int assetValue) {
		this.assetValue = assetValue;
	}

}
