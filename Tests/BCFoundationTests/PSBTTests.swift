//
//  PSBTTests.swift
//  PSBTTests 
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons Provoost on 16/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import BCFoundation
import WolfBase

class PSBTTests: XCTestCase {
    // Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
    let fingerprint: UInt32 = 0xd90c6a4f
    
    let validPSBT = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"
    
    let finalizedPSBT = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="

    // Test vector at "An updater which adds SIGHASH_ALL to the above PSBT must create this PSBT"
    let unsignedPSBT = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    
    let signedPSBT = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    
    let masterKeyXpriv = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
    
    // Paths
    let path0 = DerivationPath(string: "m/0'/0'/0'")!
    let path1 = DerivationPath(string: "m/0'/0'/1'")!
    let path2 = DerivationPath(string: "m/0'/0'/2'")!
    let path3 = DerivationPath(string: "m/0'/0'/3'")!
    let path4 = DerivationPath(string: "m/0'/0'/4'")!
    let path5 = DerivationPath(string: "m/0'/0'/5'")!
    
    // Private keys (testnet)
    let WIF_0 = "cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr" // m/0'/0'/0'
    let WIF_1 = "cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au" // m/0'/0'/1'
    let WIF_2 = "cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d" // m/0'/0'/2'
    let WIF_3 = "cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE" // m/0'/0'/3'
    
    // Public keys
    let pubKey0 = ECPublicKey(hex: "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f")!
    let pubKey1 = ECPublicKey(hex: "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7")!
    let pubKey2 = ECPublicKey(hex: "03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc")!
    let pubKey3 = ECPublicKey(hex: "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73")!
    let pubKey4 = ECPublicKey(hex: "03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771")!
    let pubKey5 = ECPublicKey(hex: "027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096")!
    
    // Singed with keys m/0'/0'/0' and m/0'/0'/2'
    let signedPSBT_0_2 = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    
    // Singed with keys m/0'/0'/1' (test vector modified for EC_FLAG_GRIND_R) and m/0'/0'/3'
    let signedPSBT_1_3 = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="

    // Mainnet multisig wallet based on BIP32 test vectors.
    // To import into Bitcoin Core (experimental descriptor wallet branch) use:
    // importdescriptors '[{"range":1000,"timestamp":"now","watchonly":true,"internal":false,"desc":"wsh(sortedmulti(2,[3442193e\/48h\/0h\/0h\/2h]xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi\/0\/*,[bd16bee5\/48h\/0h\/0h\/2h]xpub6DwQ4gBCmJZM3TaKogP41tpjuEwnMH2nWEi3PFev37LfsWPvjZrh1GfAG8xvoDYMPWGKG1oBPMCfKpkVbJtUHRaqRdCb6X6o1e9PQTVK88a\/0\/*))#75z63vc9","active":true},{"range":1000,"timestamp":"now","watchonly":true,"internal":true,"desc":"wsh(sortedmulti(2,[3442193e\/48h\/0h\/0h\/2h]xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi\/1\/*,[bd16bee5\/48h\/0h\/0h\/2h]xpub6DwQ4gBCmJZM3TaKogP41tpjuEwnMH2nWEi3PFev37LfsWPvjZrh1GfAG8xvoDYMPWGKG1oBPMCfKpkVbJtUHRaqRdCb6X6o1e9PQTVK88a\/1\/*))#8837llds","active":true}]'
    let fingerprint1: UInt32 = 0x3442193e
    let fingerprint2: UInt32 = 0xbd16bee5
    let master1 = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    let master2 = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
     let multiUnsignedPSBTWithoutChange = "cHNidP8BAFICAAAAAV/0Rj8kmS/ZB5NjsQvCKM1LTtovmhuQu2GITtz/XUFnAAAAAAD9////Af4SAAAAAAAAFgAUgPiTflaS1yPZmZleFfTq7fUwdIYAAAAAAAEBK4gTAAAAAAAAIgAg+GCObltTf4/IGC6xE89A9WS5nPmdhxcMTxrCWQdO6P0BBUdSIQIRWymltMLmSLuvwQBG3wDoMRcQlj79Fah1NMZw3Q6w+iEDkxPICphGAQSk6avIbx9z0fqYLssxciadkXQV5q7uJnVSriIGAhFbKaW0wuZIu6/BAEbfAOgxFxCWPv0VqHU0xnDdDrD6HL0WvuUwAACAAAAAgAAAAIACAACAAAAAAAAAAAAiBgOTE8gKmEYBBKTpq8hvH3PR+pguyzFyJp2RdBXmru4mdRw0Qhk+MAAAgAAAAIAAAACAAgAAgAAAAAAAAAAAAAA="
    
    let multiPSBTWithoutChangeHex = "020000000001015ff4463f24992fd9079363b10bc228cd4b4eda2f9a1b90bb61884edcff5d41670000000000fdffffff01fe1200000000000016001480f8937e5692d723d999995e15f4eaedf530748604004830450221009222d670173b1231512e96056597ab3a509e7d0919581a7e95aa7b272b69b6de022062a6b500367b0e0bd39557f5fa7e4539dc65c1c0fb4457559aea9d7efb1fba8701483045022100e02212a6eb7c6b3feb411aec6a0a8b4bce6bdca8379e03b9c5d8a80902789159022041eec69689e7eae62f5c120edfa77fe5d3a4a631f2a2e7b763603e1bb42a72560147522102115b29a5b4c2e648bbafc10046df00e8311710963efd15a87534c670dd0eb0fa21039313c80a98460104a4e9abc86f1f73d1fa982ecb3172269d917415e6aeee267552ae00000000"
    
    let multiUnsignedPSBTWithChange = "cHNidP8BAH0CAAAAAV/0Rj8kmS/ZB5NjsQvCKM1LTtovmhuQu2GITtz/XUFnAAAAAAD9////AqAPAAAAAAAAIgAg2SAanVpF/Lx6c7mjRV2xL95PrYeO1kq+yERNnuQ5oBYzAwAAAAAAABYAFID4k35Wktcj2ZmZXhX06u31MHSGAAAAAAABASuIEwAAAAAAACIAIPhgjm5bU3+PyBgusRPPQPVkuZz5nYcXDE8awlkHTuj9AQVHUiECEVsppbTC5ki7r8EARt8A6DEXEJY+/RWodTTGcN0OsPohA5MTyAqYRgEEpOmryG8fc9H6mC7LMXImnZF0Feau7iZ1Uq4iBgIRWymltMLmSLuvwQBG3wDoMRcQlj79Fah1NMZw3Q6w+hy9Fr7lMAAAgAAAAIAAAACAAgAAgAAAAAAAAAAAIgYDkxPICphGAQSk6avIbx9z0fqYLssxciadkXQV5q7uJnUcNEIZPjAAAIAAAACAAAAAgAIAAIAAAAAAAAAAAAABAUdSIQMROfTTVvMRvdrTpGn+pMYvCLB/78Bc/PK8qqIYwgg1diEDUb/gzEHWzqIxfhWictWQ+Osk5XiRlQCzWIzI+0xHd11SriICAxE59NNW8xG92tOkaf6kxi8IsH/vwFz88ryqohjCCDV2HL0WvuUwAACAAAAAgAAAAIACAACAAQAAAAIAAAAiAgNRv+DMQdbOojF+FaJy1ZD46yTleJGVALNYjMj7TEd3XRw0Qhk+MAAAgAAAAIAAAACAAgAAgAEAAAACAAAAAAA="
    
    let multiSignedPSBTWithChange = "cHNidP8BAH0CAAAAAV/0Rj8kmS/ZB5NjsQvCKM1LTtovmhuQu2GITtz/XUFnAAAAAAD9////AqAPAAAAAAAAIgAg2SAanVpF/Lx6c7mjRV2xL95PrYeO1kq+yERNnuQ5oBYzAwAAAAAAABYAFID4k35Wktcj2ZmZXhX06u31MHSGAAAAAAABASuIEwAAAAAAACIAIPhgjm5bU3+PyBgusRPPQPVkuZz5nYcXDE8awlkHTuj9IgIDkxPICphGAQSk6avIbx9z0fqYLssxciadkXQV5q7uJnVIMEUCIQCcKOgwlnCDCaYRYQQWzGu9tcZuJ9JPX3UcU0/8fBSBAgIgUBUbWh7fxytG/Fm0rQE6f08wLu3GwXbNkykAHzBR8f4BIgICEVsppbTC5ki7r8EARt8A6DEXEJY+/RWodTTGcN0OsPpHMEQCIHxzEBZRBpJ7B3lHTe6kAgDJq7d2O47710Sz4kglToOOAiA5bGwOgJXYc/y19RZ60wZWdJN/DlE84mGtoJFE0NT5bQEBBUdSIQIRWymltMLmSLuvwQBG3wDoMRcQlj79Fah1NMZw3Q6w+iEDkxPICphGAQSk6avIbx9z0fqYLssxciadkXQV5q7uJnVSriIGAhFbKaW0wuZIu6/BAEbfAOgxFxCWPv0VqHU0xnDdDrD6HL0WvuUwAACAAAAAgAAAAIACAACAAAAAAAAAAAAiBgOTE8gKmEYBBKTpq8hvH3PR+pguyzFyJp2RdBXmru4mdRw0Qhk+MAAAgAAAAIAAAACAAgAAgAAAAAAAAAAAAAEBR1IhAxE59NNW8xG92tOkaf6kxi8IsH/vwFz88ryqohjCCDV2IQNRv+DMQdbOojF+FaJy1ZD46yTleJGVALNYjMj7TEd3XVKuIgIDETn001bzEb3a06Rp/qTGLwiwf+/AXPzyvKqiGMIINXYcvRa+5TAAAIAAAACAAAAAgAIAAIABAAAAAgAAACICA1G/4MxB1s6iMX4VonLVkPjrJOV4kZUAs1iMyPtMR3ddHDRCGT4wAACAAAAAgAAAAIACAACAAQAAAAIAAAAAAA=="
    
    let multiPSBTWithChangeHex = "020000000001015ff4463f24992fd9079363b10bc228cd4b4eda2f9a1b90bb61884edcff5d41670000000000fdffffff02a00f000000000000220020d9201a9d5a45fcbc7a73b9a3455db12fde4fad878ed64abec8444d9ee439a016330300000000000016001480f8937e5692d723d999995e15f4eaedf5307486040047304402207c7310165106927b0779474deea40200c9abb7763b8efbd744b3e248254e838e0220396c6c0e8095d873fcb5f5167ad3065674937f0e513ce261ada09144d0d4f96d014830450221009c28e83096708309a611610416cc6bbdb5c66e27d24f5f751c534ffc7c148102022050151b5a1edfc72b46fc59b4ad013a7f4f302eedc6c176cd9329001f3051f1fe0147522102115b29a5b4c2e648bbafc10046df00e8311710963efd15a87534c670dd0eb0fa21039313c80a98460104a4e9abc86f1f73d1fa982ecb3172269d917415e6aeee267552ae00000000"
    
    let changeIndex999999 = "cHNidP8BAH0CAAAAAUJTCRglAyBzBJKy8g6IQZOs6mW/TAcZQBAwZ1+0nIM2AAAAAAD9////AgMLAAAAAAAAIgAgCrk8USQ4V1PTbvmbC1d4XF6tE0FHxg4DYjSyZ+v36CboAwAAAAAAABYAFMQKYgtvMZZKBJaRRzu2ymKmITLSIkwJAAABASugDwAAAAAAACIAINkgGp1aRfy8enO5o0VdsS/eT62HjtZKvshETZ7kOaAWAQVHUiEDETn001bzEb3a06Rp/qTGLwiwf+/AXPzyvKqiGMIINXYhA1G/4MxB1s6iMX4VonLVkPjrJOV4kZUAs1iMyPtMR3ddUq4iBgMROfTTVvMRvdrTpGn+pMYvCLB/78Bc/PK8qqIYwgg1dhy9Fr7lMAAAgAAAAIAAAACAAgAAgAEAAAACAAAAIgYDUb/gzEHWzqIxfhWictWQ+Osk5XiRlQCzWIzI+0xHd10cNEIZPjAAAIAAAACAAAAAgAIAAIABAAAAAgAAAAABAUdSIQJVEmEwhGKa0JX96JPOEz0ksJ7/7ogUteBmZsuzy8uRRiEC1V/QblpSYPxOd6UP4ufuL2dIy7LAn3MbVmE7q5+FXj5SriICAlUSYTCEYprQlf3ok84TPSSwnv/uiBS14GZmy7PLy5FGHDRCGT4wAACAAAAAgAAAAIACAACAAQAAAD9CDwAiAgLVX9BuWlJg/E53pQ/i5+4vZ0jLssCfcxtWYTurn4VePhy9Fr7lMAAAgAAAAIAAAACAAgAAgAEAAAA/Qg8AAAA="
    
    let changeIndex1000000 = "cHNidP8BAH0CAAAAAUJTCRglAyBzBJKy8g6IQZOs6mW/TAcZQBAwZ1+0nIM2AAAAAAD9////AugDAAAAAAAAFgAUxApiC28xlkoElpFHO7bKYqYhMtIDCwAAAAAAACIAIJdT/Bk+sg3L4UXNnCMQ+76c531xAF4pGWkhztn4evpsIkwJAAABASugDwAAAAAAACIAINkgGp1aRfy8enO5o0VdsS/eT62HjtZKvshETZ7kOaAWAQVHUiEDETn001bzEb3a06Rp/qTGLwiwf+/AXPzyvKqiGMIINXYhA1G/4MxB1s6iMX4VonLVkPjrJOV4kZUAs1iMyPtMR3ddUq4iBgMROfTTVvMRvdrTpGn+pMYvCLB/78Bc/PK8qqIYwgg1dhy9Fr7lMAAAgAAAAIAAAACAAgAAgAEAAAACAAAAIgYDUb/gzEHWzqIxfhWictWQ+Osk5XiRlQCzWIzI+0xHd10cNEIZPjAAAIAAAACAAAAAgAIAAIABAAAAAgAAAAAAAQFHUiEC1/v7nPnBRo1jlhIyjJPwMaBdjZhiYYVxQu52lLXNDeAhA4NzKqUnt/XjzyTC7BzuKiGV96QPVF151rJuX4ZV59vNUq4iAgLX+/uc+cFGjWOWEjKMk/AxoF2NmGJhhXFC7naUtc0N4Bw0Qhk+MAAAgAAAAIAAAACAAgAAgAEAAABAQg8AIgIDg3MqpSe39ePPJMLsHO4qIZX3pA9UXXnWsm5fhlXn280cvRa+5TAAAIAAAACAAAAAgAIAAIABAAAAQEIPAAA="
    
    func testInvalidPSBT(_ psbt: String) {
        XCTAssertNil(PSBT(base64: psbt))
    }
    
    func testParseTooShortPSBT() {
        testInvalidPSBT("")
    }
    
    func testInvalidCharacters() {
        testInvalidPSBT("💩")
    }

    func testParseBase64() {
        let psbt = PSBT(base64: validPSBT)!
        XCTAssertEqual(psbt†, validPSBT)
    }
    
    func testParseBinary() {
        let psbtData = Data(base64Encoded: validPSBT)!
        let psbt = PSBT(psbtData)!
        XCTAssertEqual(psbt†, validPSBT)
        XCTAssertEqual(psbt.data, psbtData)
    }
    
    func testInvalidPSBT() {
    testInvalidPSBT("AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA==")
    }
    
    func testComplete() {
        let incompletePSBT = PSBT(base64: validPSBT)!
        let completePSBT = PSBT(base64: finalizedPSBT)!
        XCTAssertFalse(incompletePSBT.isFinalized)
        XCTAssertFalse(PSBT(base64: unsignedPSBT)!.isFinalized)
        XCTAssertFalse(PSBT(base64: signedPSBT_0_2)!.isFinalized)
        XCTAssertTrue(completePSBT.isFinalized)
    }
    
    func testExtractTransaction() {
        let incompletePSBT = PSBT(base64: validPSBT)!
        XCTAssertNil(incompletePSBT.finalizedTransaction())
        
        let completePSBT = PSBT(base64: finalizedPSBT)!
        let transaction = completePSBT.finalizedTransaction()!
        XCTAssertEqual(transaction†, "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000")
    }
    
    func testSignWithKey() {
        let privKey0 = WIF(WIF_0)!.key
        let privKey1 = WIF(WIF_1)!.key
        let privKey2 = WIF(WIF_2)!.key
        let privKey3 = WIF(WIF_3)!.key
        let psbt1 = PSBT(base64: unsignedPSBT)!
        let psbt2 = PSBT(base64: unsignedPSBT)!
        let expectedPSBT_0_2 = PSBT(base64: signedPSBT_0_2)!
        let expectedPSBT_1_3 = PSBT(base64: signedPSBT_1_3)!

        let p102 = psbt1.signed(with: privKey0)!.signed(with: privKey2)!
        XCTAssertEqual(p102†, expectedPSBT_0_2†)

        let p213 = psbt2.signed(with: privKey1)!.signed(with: privKey3)!
        XCTAssertEqual(p213†, expectedPSBT_1_3†)
    }
    
    func testInputs() {
        let psbt = PSBT(base64: unsignedPSBT)!
        XCTAssertEqual(psbt.inputs.count, 2)
    }
    
    func testOutput() {
        let psbt = PSBT(base64: unsignedPSBT)!
        XCTAssertEqual(psbt.outputs.count, 2)
    }
    
    func testKeyPaths() {
        let expectedOrigin0 = DerivationPath(steps: path0.steps, origin: .fingerprint(fingerprint))
        let expectedOrigin1 = DerivationPath(steps: path1.steps, origin: .fingerprint(fingerprint))
        let expectedOrigin2 = DerivationPath(steps: path2.steps, origin: .fingerprint(fingerprint))
        let expectedOrigin3 = DerivationPath(steps: path3.steps, origin: .fingerprint(fingerprint))
        let expectedOrigin4 = DerivationPath(steps: path4.steps, origin: .fingerprint(fingerprint))
        let expectedOrigin5 = DerivationPath(steps: path5.steps, origin: .fingerprint(fingerprint))
        let psbt = PSBT(base64: unsignedPSBT)!
        // Check inputs
        XCTAssertEqual(psbt.inputs.count, 2)
        let inOrigins0 = psbt.inputs[0].origins
        XCTAssertEqual(inOrigins0.count, 2)
        XCTAssertEqual(inOrigins0.first(where: {$0.key == pubKey0})!.path, expectedOrigin0)
        XCTAssertEqual(inOrigins0.first(where: {$0.key == pubKey1})!.path, expectedOrigin1)
        let inOrigins1 = psbt.inputs[1].origins
        XCTAssertEqual(inOrigins1.count, 2)
        XCTAssertEqual(inOrigins1.first(where: {$0.key == pubKey3})!.path, expectedOrigin3)
        XCTAssertEqual(inOrigins1.first(where: {$0.key == pubKey2})!.path, expectedOrigin2)
        // Check outputs
        XCTAssertEqual(psbt.outputs.count, 2)
        let outOrigins0 = psbt.outputs[0].origins
        XCTAssertEqual(outOrigins0.count, 1)
        XCTAssertEqual(outOrigins0.first(where: {$0.key == pubKey4})!.path, expectedOrigin4)
        let outOrigins1 = psbt.outputs[1].origins
        XCTAssertEqual(outOrigins1.count, 1)
        XCTAssertEqual(outOrigins1.first(where: {$0.key == pubKey5})!.path, expectedOrigin5)
    }
   
    func testCanSign() throws {
        let masterKey = try HDKey(base58: masterKeyXpriv)
        let psbt = PSBT(base64: unsignedPSBT)!
        for input in psbt.inputs {
            XCTAssertTrue(input.canSign(with: masterKey))
        }
    }

    func testFinalize() {
        let psbt = PSBT(base64: signedPSBT)!
        let expected = PSBT(base64: finalizedPSBT)!
        let finalized = psbt.finalized()!
        XCTAssertEqual(finalized, expected)
    }
    
    func testSignWithHDKey() throws {
        let psbt = PSBT(base64: unsignedPSBT)!
        let masterKey = try HDKey(base58: masterKeyXpriv)
        let signed = psbt.signed(with: masterKey)!
        let finalized = signed.finalized()!
        XCTAssertTrue(finalized.isFinalized)
    }
    
    // In the previous example all inputs were part of the same BIP32 master key.
    // In this example we sign with seperate keys, more representative of a real
    // setup with multiple wallets.
    func testCanSignNeutered() throws {
        let us = try HDKey(base58: "xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi", overrideOriginFingerprint: 0x3442193e)
        let psbt = PSBT(base64: multiUnsignedPSBTWithChange)!
        for input in psbt.inputs {
            XCTAssertTrue(input.canSign(with: us))
        }
    }
    
    func testSignRealMultisigWithHDKey() throws {
        let keySigner1 = try HDKey(base58: master1)
        let keySigner2 = try HDKey(base58: master2)
        let psbtWithoutChange = PSBT(base64: multiUnsignedPSBTWithoutChange)!
        let psbtWithChange = PSBT(base64: multiUnsignedPSBTWithChange)!
        
        let psbtWithoutChangedSigned = psbtWithoutChange.signed(with: keySigner1)!.signed(with: keySigner2)!
        let psbtWithoutChangedFinalized = psbtWithoutChangedSigned.finalized()!
        XCTAssertTrue(psbtWithoutChangedFinalized.isFinalized)
        XCTAssertEqual(psbtWithoutChangedFinalized.finalizedTransaction()†, multiPSBTWithoutChangeHex)

        let psbtWithChangeSigned = psbtWithChange.signed(with: keySigner1)!.signed(with: keySigner2)!
        XCTAssertEqual(psbtWithChangeSigned†, multiSignedPSBTWithChange)
        let psbtWithChangedFinalized = psbtWithChangeSigned.finalized()!
        XCTAssertEqual(psbtWithChangedFinalized.finalizedTransaction()†, multiPSBTWithChangeHex)
        
        XCTAssertEqual(psbtWithChangedFinalized.outputs[0].txOutput.amount, 4000)
        XCTAssertEqual(psbtWithChangedFinalized.outputs[0].txOutput.address(network: .mainnet), "bc1qmysp4826gh7tc7nnhx352hd39l0yltv83mty40kgg3xeaepe5qtq4c50qe")

        XCTAssertEqual(psbtWithChangedFinalized.outputs[1].txOutput.amount, 819)
        XCTAssertEqual(psbtWithChangedFinalized.outputs[1].txOutput.address(network: .mainnet), "bc1qsrufxljkjttj8kven90pta82ah6nqayxfr8p9h")
    }
    
    func testIsChange() throws {
//        let us = try HDKey(base58: master1)
//        let cosigner = try HDKey(base58: master2)
        var psbt = PSBT(base64: multiUnsignedPSBTWithChange)!
//        XCTAssertTrue(psbt.outputs[0].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
//        XCTAssertFalse(psbt.outputs[1].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
        XCTAssertTrue(psbt.outputs[0].isChange)
        XCTAssertFalse(psbt.outputs[1].isChange)

        // Test maximum permitted change index
        psbt = PSBT(base64: changeIndex999999)!
//        XCTAssertTrue(psbt.outputs[0].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
//        XCTAssertFalse(psbt.outputs[1].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
        XCTAssertTrue(psbt.outputs[0].isChange)
        XCTAssertFalse(psbt.outputs[1].isChange)

        // Test out of bounds change index
        psbt = PSBT(base64: changeIndex1000000)!
//        XCTAssertFalse(psbt.outputs[0].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
//        XCTAssertFalse(psbt.outputs[1].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
        XCTAssertFalse(psbt.outputs[0].isChange)
        XCTAssertFalse(psbt.outputs[1].isChange)
    }
    
    func testIsChangeWithNeuteredCosignerKey() throws {
//        let us = try HDKey(base58: master1)
//        let cosigner = try HDKey(base58: "xpub6DwQ4gBCmJZM3TaKogP41tpjuEwnMH2nWEi3PFev37LfsWPvjZrh1GfAG8xvoDYMPWGKG1oBPMCfKpkVbJtUHRaqRdCb6X6o1e9PQTVK88a", overrideOriginFingerprint: 0xbd16bee5)
        let psbt = PSBT(base64: multiUnsignedPSBTWithChange)!
//        XCTAssertTrue(psbt.outputs[0].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
//        XCTAssertFalse(psbt.outputs[1].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
        XCTAssertTrue(psbt.outputs[0].isChange)
        XCTAssertFalse(psbt.outputs[1].isChange)
    }
    
    func testIsChangeWithNeuteredAllKeys() throws {
//        let us = try HDKey(base58: "xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi", overrideOriginFingerprint: 0x3442193e)
//        let cosigner = try HDKey(base58: "xpub6DwQ4gBCmJZM3TaKogP41tpjuEwnMH2nWEi3PFev37LfsWPvjZrh1GfAG8xvoDYMPWGKG1oBPMCfKpkVbJtUHRaqRdCb6X6o1e9PQTVK88a", overrideOriginFingerprint: 0xbd16bee5)
        let psbt = PSBT(base64: multiUnsignedPSBTWithChange)!
//        XCTAssertTrue(psbt.outputs[0].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
//        XCTAssertFalse(psbt.outputs[1].isChange(signer: us, inputs: psbt.inputs, cosigners: [cosigner], threshold: 2))
        XCTAssertTrue(psbt.outputs[0].isChange)
        XCTAssertFalse(psbt.outputs[1].isChange)
    }
    
    func testGetTransactionFee() {
        let psbt = PSBT(base64: multiUnsignedPSBTWithChange)!
        XCTAssertEqual(psbt.fee, 181)
    }
    
    func printPSBT(_ psbt: PSBT, inputSigning: [PSBTInputSigning<NamedSeed>], outputSigning: [PSBTOutputSigning<NamedSeed>], network: Network) {
        print("\n===== PSBT")

        print("TOTAL SENT: BTC \((psbt.totalSent?.btcFormat)†)")
        print("TOTAL CHANGE: BTC \((psbt.totalChange?.btcFormat)†)")
        print()
        print("TOTAL IN: BTC \((psbt.totalIn?.btcFormat)†)")
        print("TOTAL OUT: BTC \((psbt.totalOut?.btcFormat)†)")
        print("MINING FEE: BTC \((psbt.fee?.btcFormat)†)")
        print("\n=== INPUTS")

        for (index, info) in inputSigning.enumerated() {
            let input = info.input
            let signingStatuses = info.statuses
            print("--- INPUT #\(index + 1)")
            //print(input)
            if let amount = input.amount?.btcFormat {
                print("Amount: BTC \(amount)")
            }
            if let address = input.address(network: network) {
                print("From Address: \(address)")
            }
            if
                !input.witnessStack.isEmpty,
                let (n, m) = input.witnessStack[0]?.multisigInfo
            {
                print("Multisig \(n) of \(m)")
            }
            for status in signingStatuses {
                print(status.statusString)
            }
        }

        print("\n=== OUTPUTS")
        for (index, info) in outputSigning.enumerated() {
            let output = info.output
            let signingStatuses = info.statuses
            print("--- OUTPUT #\(index + 1)")
            //print(output)
            print("Amount: BTC \(output.amount.btcFormat) \(output.isChange ? "CHANGE" : "")")
            print("To Address: \(output.address(network: network))")
            if let (n, m) = output.txOutput.scriptPubKey.multisigInfo {
                print("Multisig \(n) of \(m)")
            }
            for status in signingStatuses {
                print(status.statusString)
            }
        }
        
        print("-----")
    }
    
    func psbtSession(_ psbt: PSBT, seeds: [NamedSeed], network: Network, expectedRequest: String, expectedResponse: String) {
        let cid = CID(‡"d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")!
        let requestBody = PSBTSignatureRequestBody(psbt: psbt)
        let request = TransactionRequest(id: cid, body: requestBody)
        XCTAssertEqual(request.envelope.urString, expectedRequest)
        
        let inputSigning = psbt.inputSigning(signers: seeds)
        let outputSigning = psbt.outputSigning(signers: seeds)

        print("\n======= BEFORE SIGNING")
        printPSBT(psbt, inputSigning: inputSigning, outputSigning: outputSigning, network: network)
        
        guard let signedPSBT = psbt.signed(with: inputSigning) else {
            print("\n======= UNABLE TO SIGN PSBT")
            return
        }
        
        print("\n======= AFTER SIGNING")
        let updatedInputSigning = signedPSBT.inputSigning(signers: seeds)
        printPSBT(signedPSBT, inputSigning: updatedInputSigning, outputSigning: outputSigning, network: network)
        
        let response = TransactionResponse(id: cid, result: signedPSBT)
        XCTAssertEqual(response.envelope.urString, expectedResponse)
        
        XCTAssertNotEqual(psbt.data, signedPSBT.data)
    }

    let alice = NamedSeed("Alice", Seed(hex: "82f32c855d3d542256180810797e0073")!)
    let bob = NamedSeed("Bob", Seed(hex: "187a5973c64d359c836eba466a44db7b")!)

    func testPSBTSession1of2() {
        // A PSBT that can be fully signed by Alice or Bob (1 of 2).
        let psbt1of2 = PSBT(base64: "cHNidP8BAIkCAAAAAQPwB5cTkHMnKTqvqrrLPS1eLOAftT5vFpGcmc/xOXbNAAAAAAD9////Aqk7AQAAAAAAIgAgvrSaYkbuN5hy0mVXVgDRa+5KruKkRvab01aabj0wgA7oAwAAAAAAACIAIPET3raA+LQKJEoBaMJuHbq+/sVlZ7wAKqhYrhBRqF7GAAAAAAABAStQQAEAAAAAACIAIGppYhdefSa0Tt20ryHx+9D6hYu1x22rAREe77meFBePAQVHUSECBea9jkSoCw14R3q/7TwiVNGLcj0FC+ifMpXQe3Xw3pUhA1NZQ82ujgajfnWaDcwQwQQnqdA2pJnhnnoAfY7hN9Y/Uq4iBgIF5r2ORKgLDXhHer/tPCJU0YtyPQUL6J8yldB7dfDelRxVAWsvMAAAgAEAAIAAAACAAgAAgAAAAAABAAAAIgYDU1lDza6OBqN+dZoNzBDBBCep0DakmeGeegB9juE31j8c3lhO/TAAAIABAACAAAAAgAIAAIAAAAAAAQAAAAABAUdRIQJ97wKVQ/jja6DUlf6gkEjHukxkcTmIRp4Q6MZnI/DOZiED9+crp4WXakT0kPqDtpDXzEHRdMmm1sNthOQfj/n86klSriICAn3vApVD+ONroNSV/qCQSMe6TGRxOYhGnhDoxmcj8M5mHFUBay8wAACAAQAAgAAAAIACAACAAQAAAAIAAAAiAgP35yunhZdqRPSQ+oO2kNfMQdF0yabWw22E5B+P+fzqSRzeWE79MAAAgAEAAIAAAACAAgAAgAEAAAACAAAAAAA=")!
        let psbt1of2ExpectedRequest = "ur:envelope/lftpsptpcstptktaadethdcxtygshybkzcecfhflpfdlhdonotoentnydmzsidmkindlldjztdmoeyishknybtbstpsptpsolftpsptpsgcsietpsplftpsptpcstpttcsiytpsptpsolftpsptpcstptdcssntpsplftpsptpcshkaohgjojkidjyzmadaeldaoaeaeaeadaxwtatmsbwmhjkdidtftpepkrdsbfsdphydwvtctrefmjlcmmensnltkwneskosnaeaeaeaeaezczmzmzmaoptfradaeaeaeaeaecpaecxrnqznyidfgwyemmkjptdihhghfaettjewygeplvooxfgynndtehfnyjtfsdylabavsaxaeaeaeaeaeaecpaecxwnbwuerplayaqzbkdkgeadissajtcardrnzeskihiorfaedrpdhdplbegypdhyswaeaeaeaeaeadaddngdfzadaeaeaeaeaecpaecximinidchhykidsqzglutqzpeclwnzotizslplurestjnpyadbyckwsrhnnbbchmyadahflgyclaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdclaxguhkfxsnplmnamotkbkpnybtsfbeseaadipttienoxnlvynnknaekimnvyemtbfhgmplcpamaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdcegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaecpamaxguhkfxsnplmnamotkbkpnybtsfbeseaadipttienoxnlvynnknaekimnvyemtbfhceuehdglzcdyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaeaeadadflgyclaokiwsaomdfxyavljenbtymdzenbmhfdstrdgsiejseslofgnnbevsswiocnwttoiyclaxylvddnoslpmsimfywkmhzslsrpmhtssffpttjysooltbsrjnlrvectmyytztwdgagmplcpaoaokiwsaomdfxyavljenbtymdzenbmhfdstrdgsiejseslofgnnbevsswiocnwttoiycegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaoaeaeaecpaoaxylvddnoslpmsimfywkmhzslsrpmhtssffpttjysooltbsrjnlrvectmyytztwdgaceuehdglzcdyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaoaeaeaeaeaetpsptpsolftpsptpsgadtpsptpsgcfadzsswrdhppl"
        let psbt1of2ExpectedResponse = "ur:envelope/lftpsptpcstptitaadethdcxtygshybkzcecfhflpfdlhdonotoentnydmzsidmkindlldjztdmoeyishknybtbstpsptpsolftpsptpsgcsihtpsplftpsptpcshkaosajojkidjyzmadaeldaoaeaeaeadaxwtatmsbwmhjkdidtftpepkrdsbfsdphydwvtctrefmjlcmmensnltkwneskosnaeaeaeaeaezczmzmzmaoptfradaeaeaeaeaecpaecxrnqznyidfgwyemmkjptdihhghfaettjewygeplvooxfgynndtehfnyjtfsdylabavsaxaeaeaeaeaeaecpaecxwnbwuerplayaqzbkdkgeadissajtcardrnzeskihiorfaedrpdhdplbegypdhyswaeaeaeaeaeadaddngdfzadaeaeaeaeaecpaecximinidchhykidsqzglutqzpeclwnzotizslplurestjnpyadbyckwsrhnnbbchmycpaoaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdfldyfyaocxcnctashskoaddyveprdirkmnmdhshtplinasluyldmolbntdvsswbbneesaewtimaocxjlbwvydejptbqdsnkpfrtpdrdezsioiomtpfhdjzbnnnlbtinsfsfgpdlaaopesgadadahflgyclaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdclaxguhkfxsnplmnamotkbkpnybtsfbeseaadipttienoxnlvynnknaekimnvyemtbfhgmplcpamaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdcegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaecpamaxguhkfxsnplmnamotkbkpnybtsfbeseaadipttienoxnlvynnknaekimnvyemtbfhceuehdglzcdyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaeaeadadflgyclaokiwsaomdfxyavljenbtymdzenbmhfdstrdgsiejseslofgnnbevsswiocnwttoiyclaxylvddnoslpmsimfywkmhzslsrpmhtssffpttjysooltbsrjnlrvectmyytztwdgagmplcpaoaokiwsaomdfxyavljenbtymdzenbmhfdstrdgsiejseslofgnnbevsswiocnwttoiycegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaoaeaeaecpaoaxylvddnoslpmsimfywkmhzslsrpmhtssffpttjysooltbsrjnlrvectmyytztwdgaceuehdglzcdyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaoaeaeaeaeaetpsptpsolftpsptpsgadtpsptpsgcfadzsadrdyadt"
        psbtSession(psbt1of2, seeds: [alice, bob], network: .testnet, expectedRequest: psbt1of2ExpectedRequest, expectedResponse: psbt1of2ExpectedResponse)
    }
    
    func testPSBTSession2of2() {
        // A PSBT that must be signed by Alice and Bob (2 of 2).
        let psbt2of2 = PSBT(base64: "cHNidP8BAH0CAAAAAVDiIuDv/6eKF/3KA2FyMzrLVV5pk3G2NEhF73B5cHZCAAAAAAD9////AroQAQAAAAAAIgAgEJHB5dt2HT9eYRRt+DRB1VesE3u4PQnVjxslEzH30RQQJwAAAAAAABYAFP+dpWfmLzDqhlT6HV+9R774474TAAAAAAABASuAOAEAAAAAACIAIOqI/uwvV9W/A0OzXJIq/7ez8/Djlu5044ADEcHKoxeJAQVHUiECBea9jkSoCw14R3q/7TwiVNGLcj0FC+ifMpXQe3Xw3pUhAwxRX5TBJXgf73IHRs8KO3ogIAPLIGg4F5krQxtG4s23Uq4iBgIF5r2ORKgLDXhHer/tPCJU0YtyPQUL6J8yldB7dfDelRxVAWsvMAAAgAEAAIAAAACAAgAAgAAAAAABAAAAIgYDDFFflMEleB/vcgdGzwo7eiAgA8sgaDgXmStDG0bizbccp+jQbjAAAIABAACAAAAAgAIAAIAAAAAAAQAAAAABAUdSIQIotmH/B/ZiUBfIrNaQfgfTQYH8pMLZyaqeuXwhI6KUNSEC5LHB9GmJkMT3B59mRaTvNJqjEfxARIb5j/xjUYVKa89SriICAii2Yf8H9mJQF8is1pB+B9NBgfykwtnJqp65fCEjopQ1HFUBay8wAACAAQAAgAAAAIACAACAAQAAAAMAAAAiAgLkscH0aYmQxPcHn2ZFpO80mqMR/EBEhvmP/GNRhUprzxyn6NBuMAAAgAEAAIAAAACAAgAAgAEAAAADAAAAAAA=")!
        let psbt2of2ExpectedRequest = "ur:envelope/lftpsptpcstptktaadethdcxtygshybkzcecfhflpfdlhdonotoentnydmzsidmkindlldjztdmoeyishknybtbstpsptpsolftpsptpsgcsietpsplftpsptpcstpttcsiytpsptpsolftpsptpcstptdcssntpsplftpsptpcshkaogrjojkidjyzmadaekiaoaeaeaeadgdvocpvtwszmoslechzcsgaxhsjpeoftsbgohyinmujsrpeefdfewsjokkjokofwaeaeaeaeaezczmzmzmaordbeadaeaeaeaeaecpaecxbemesevwuykocafhhyhsbbjnyaeefptlhgpsbwkgrofsastlmycwdabwehylttbbbediaeaeaeaeaeaecmaebbzmntoniovadldywdlnghzscaheryflrnyavlrnbwaeaeaeaeaeadaddnlaetadaeaeaeaeaecpaecxwdlozewpdlhgtlrsaxfxqdhhmodrzmrlqdwfwtvlmtwyjyvllaaxbysesgotchldadahflgmclaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdclaxbngyhemwsedaksctwsjpatfgtkbkfrkncxcxaxsbcxisetchnldnfxcwfgvosnrlgmplcpamaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdcegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaecpamaxbngyhemwsedaksctwsjpatfgtkbkfrkncxcxaxsbcxisetchnldnfxcwfgvosnrlceosvstijtdyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaeaeadadflgmclaoderphszmatynidgdchsppstbmhkbattefplyztoxsatasopknnrhkeclcnoemwecclaovepasewkinldmhssylatneiyfeoxwseenyotbyztfzfylnytmyztiagylpgejetkgmplcpaoaoderphszmatynidgdchsppstbmhkbattefplyztoxsatasopknnrhkeclcnoemweccegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaxaeaeaecpaoaovepasewkinldmhssylatneiyfeoxwseenyotbyztfzfylnytmyztiagylpgejetkceosvstijtdyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaxaeaeaeaeaetpsptpsolftpsptpsgadtpsptpsgcfadzsgosepdah"
        let psbt2of2ExpectedResponse = "ur:envelope/lftpsptpcstptitaadethdcxtygshybkzcecfhflpfdlhdonotoentnydmzsidmkindlldjztdmoeyishknybtbstpsptpsolftpsptpsgcsihtpsplftpsptpcshkaxcnjojkidjyzmadaekiaoaeaeaeadgdvocpvtwszmoslechzcsgaxhsjpeoftsbgohyinmujsrpeefdfewsjokkjokofwaeaeaeaeaezczmzmzmaordbeadaeaeaeaeaecpaecxbemesevwuykocafhhyhsbbjnyaeefptlhgpsbwkgrofsastlmycwdabwehylttbbbediaeaeaeaeaeaecmaebbzmntoniovadldywdlnghzscaheryflrnyavlrnbwaeaeaeaeaeadaddnlaetadaeaeaeaeaecpaecxwdlozewpdlhgtlrsaxfxqdhhmodrzmrlqdwfwtvlmtwyjyvllaaxbysesgotchldcpaoaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdfddyfeaoclaemyfprobarkytrllnvslagukitdtlbkwswsurlelppkfgpdptwfahdmlnetfzaxisaocxjtoyjtlsntinievytbrdlrrsmtbsfpdtlakpoyzmjpgllnkbpleobecpsbfwgwbkadcpaoaxbngyhemwsedaksctwsjpatfgtkbkfrkncxcxaxsbcxisetchnldnfxcwfgvosnrlfddyfeaoclaemwvwinknzcutswguynisgybgjeluyatbhywtlgwfjnwmylptjygovadlvdsshtkeaocxksdsrhtantfegyuehdehjzdnleoxbekekbfhaoierkghrlcmmyjsfeadrpeslksfadadahflgmclaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdclaxbngyhemwsedaksctwsjpatfgtkbkfrkncxcxaxsbcxisetchnldnfxcwfgvosnrlgmplcpamaoahvarymnfypdbdbtksflknrswefncpghttlujpfsahbdvsneeymdtikgkpwtuemdcegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaecpamaxbngyhemwsedaksctwsjpatfgtkbkfrkncxcxaxsbcxisetchnldnfxcwfgvosnrlceosvstijtdyaeaelaadaeaelaaeaeaelaaoaeaelaaeaeaeaeadaeaeaeaeadadflgmclaoderphszmatynidgdchsppstbmhkbattefplyztoxsatasopknnrhkeclcnoemwecclaovepasewkinldmhssylatneiyfeoxwseenyotbyztfzfylnytmyztiagylpgejetkgmplcpaoaoderphszmatynidgdchsppstbmhkbattefplyztoxsatasopknnrhkeclcnoemweccegoadjedldyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaxaeaeaecpaoaovepasewkinldmhssylatneiyfeoxwseenyotbyztfzfylnytmyztiagylpgejetkceosvstijtdyaeaelaadaeaelaaeaeaelaaoaeaelaadaeaeaeaxaeaeaeaeaetpsptpsolftpsptpsgadtpsptpsgcfadzslgvwtece"
        psbtSession(psbt2of2, seeds: [alice, bob], network: .testnet, expectedRequest: psbt2of2ExpectedRequest, expectedResponse: psbt2of2ExpectedResponse)
    }
}

extension PSBTSigningStatus where SignerType == NamedSeed {
    var statusString: String {
        switch status {
        case .isSignedBy(let seed):
            return "Signed by: \(seed.name) \(origin.path)"
        case .isSignedByUnknown:
            return "Signed by unknown: \(origin.path)"
        case .canBeSignedBy(let seed):
            return "To be signed by: \(seed.name) \(origin.path) \(origin.isChange ? "CHANGE" : "")"
        case .noKnownSigner:
            return "No known signer for: \(origin.path) \(origin.isChange ? "CHANGE" : "")"
        }
    }
}

struct NamedSeed: CustomStringConvertible, Hashable {
    let name: String
    let account: AccountDerivations

    var seed: Seed {
        account.seed!
    }
    
    var masterKey: HDKey {
        account.masterKey!
    }
    
    var masterKeyFingerprint: UInt32 {
        masterKey.keyFingerprint
    }
    
    init(_ name: String, _ seed: Seed) {
        self.account = AccountDerivations(seed: seed, useInfo: .init(), account: 0)
        self.name = name
    }
    
    var description: String {
        "Seed(\(name) \(seed.hex) \(masterKeyFingerprint.hex))"
    }
    
    static func == (lhs: NamedSeed, rhs: NamedSeed) -> Bool {
        return lhs.seed.data == rhs.seed.data
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(seed.data)
    }
}

extension NamedSeed: PSBTSigner {
}
