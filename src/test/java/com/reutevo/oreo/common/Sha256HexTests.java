package com.reutevo.oreo.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Sha256HexTests {

	@Test
	void hashesKnownSha256VectorAsLowercaseHex() {
		assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				Sha256Hex.digest("abc"));
	}

	@Test
	void hashesEmptyInput() {
		assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Sha256Hex.digest(""));
	}
}
