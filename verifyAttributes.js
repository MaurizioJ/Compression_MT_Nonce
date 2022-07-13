import process from 'process';
import { createRequire } from 'module';
import {createMerkleTree,CryptoSHALeaves, CryptoSHATree} from './creationMekleTree.js'

const require = createRequire(import.meta.url);
const util = require('util');
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const { MerkleTree } = require('merkletreejs')
import { decompress } from 'compress-json'
const zlib = require('zlib')


let crypto;
var config =require('../config.json');

crypto = require('crypto');
export const verifyAttributes = async (VCs, VP)  => {

    var listHashedValue =[]
    var listProofDecompress =[]
    let listValue= VP.vp.attributes
    const listProof = VP.vp.proof

    for(const credential of VCs){
        var credVC = credential.credentialSubject
        var root = credVC["root"] // recupero il nodo radice
        for(let i=0; i<listValue.length;i++){
            let buf= Buffer.from(listProof[i].listPathNodes,'base64') // converto la proof da string a buffer
             console.log("formato buffer da decomprimere")
             console.log(buf)
            let decompression = zlib.brotliDecompressSync(buf) // decompressione

            let proofJson = decompression.toString() // converto in string perché il metodo unmarshal necessita di un parametro json

            listProofDecompress[i] = MerkleTree.unmarshalProof(proofJson)
           let obj=  await CryptoSHALeaves(listValue[i],listProof[i].nonceLeaves)
            listHashedValue.push(obj.hashedLeaves)
        }

        for(let i=0;i<listProofDecompress.length;i++){ // scorro la lista dei valori che voglio verificare

            if(MerkleTree.verify(listProofDecompress[i], listHashedValue[i].toString(), root,CryptoSHATree)){
                 console.log("Il nodo foglia " + listValue[i] + " è stato verificato con SUCCESSO");
            } 
            else {
                console.log("Il nodo foglia " + listValue[i] + " NON è stato verificato con SUCCESSO");
                return;
            } 

        }

    }

return ;
}