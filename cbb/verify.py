"""Offline package verification. No server, database or network access required."""
import base64
import hashlib
import zipfile
from pathlib import Path
from .crypto import canon, sha, strict_json, verify_signature


def verify_package(path, public_key, *, trusted_checkpoint=None, witness_bundle=None, witness_public_key=None):
    if (witness_bundle is None) != (witness_public_key is None):
        raise ValueError("Supply both the witness bundle and the separately trusted witness public key")
    failures=[]
    assurance = "LOCAL_CHECK_ONLY"
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise ValueError("Duplicate ZIP members")
        if len(names)>100000 or sum(i.file_size for i in z.infolist())>8*1024**3:raise ValueError("Package exceeds verification budget")
        def document(name):
            if z.getinfo(name).file_size>64*1024**2:raise ValueError("Metadata exceeds 64 MiB budget")
            return strict_json(z.read(name))
        manifest=document("manifest.json")
        signed=verify_signature(document("manifest.signature.json"),"CBB-EXPORT-v1",public_key)
        if canon(manifest)!=canon(signed):raise ValueError("Manifest signature payload differs")
        expected={"manifest.json","manifest.signature.json"}
        for item in manifest["files"]:
            name=item["path"]
            if name in expected or name.startswith(("/","\\")) or ".." in Path(name).parts:raise ValueError("Invalid manifest path")
            expected.add(name)
            h=hashlib.sha256();length=0
            with z.open(name) as f:
                for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk);length+=len(chunk)
            if h.hexdigest()!=item["sha256"] or length!=int(item["size"]):failures.append({"code":"FILE_MODIFIED","path":name})
        if set(names)!=expected:failures.append({"code":"UNLISTED_OR_MISSING_FILES"})
        checkpoint_document = document("checkpoint.json")
        checkpoint=verify_signature(checkpoint_document,"CBB-CHECKPOINT-v1",public_key)
        if trusted_checkpoint is not None:
            retained = verify_signature(trusted_checkpoint, "CBB-CHECKPOINT-v1", public_key)
            if canon(retained) != canon(checkpoint):
                failures.append({"code": "RETAINED_CHECKPOINT_MISMATCH"})
            else:
                assurance = "RETAINED_CHECKPOINT_MATCHED"
        if witness_bundle is not None:
            if witness_public_key == public_key:
                raise ValueError("The witness key must differ from the deployment signing key")
            witnessed_document = witness_bundle["checkpoint"]
            witnessed = verify_signature(witnessed_document, "CBB-CHECKPOINT-v1", public_key)
            receipt = verify_signature(witness_bundle["receipt"], "CBB-WITNESS-v1", witness_public_key)
            fields = ("deployment_id", "checkpoint_id", "checkpoint_seq")
            if (canon(witnessed) != canon(checkpoint)
                    or receipt.get("receipt_version") != "1.0"
                    or any(receipt.get(field) != checkpoint[field] for field in fields)
                    or receipt.get("checkpoint_sha256") != sha(canon(checkpoint_document))):
                failures.append({"code": "WITNESSED_CHECKPOINT_MISMATCH"})
            else:
                assurance = "WITNESS_RECEIPT_VERIFIED"
        chain=next(x for x in checkpoint["chains"] if x["purpose"]=="evidence")
        previous=chain["genesis"];sequence=0;proofs={}
        for p in document("proof.json"):
            sequence+=1
            digest=sha(b"CBB-RECORD-v1\0"+bytes.fromhex(previous)+sequence.to_bytes(8,"big")+bytes.fromhex(p["envelope_sha256"]))
            if int(p["sequence"])!=sequence or p["previous_hash"]!=previous or p["record_hash"]!=digest:failures.append({"code":"CHAIN_PROOF_INVALID","sequence":sequence})
            previous=digest;proofs[sequence]=p
        if sequence!=int(chain["sequence"]) or previous!=chain["head_hash"]:failures.append({"code":"CHECKPOINT_MISMATCH"})
        for item in manifest["evidence"]:
            envelope=z.read(item["envelope_path"]);env=strict_json(envelope);proof=proofs.get(int(item["sequence"]),{})
            if canon(env)!=envelope or env["evidence_id"]!=item["id"] or sha(envelope)!=proof.get("envelope_sha256") or item["record_hash"]!=proof.get("record_hash"):failures.append({"code":"EVIDENCE_PROOF_INVALID","id":item["id"]})
            if sha(z.read(item["raw_path"]))!=env["raw"]["sha256"]:failures.append({"code":"RAW_HASH_MISMATCH","id":item["id"]})
    return {"status":"INVALID" if failures else "VALID","assurance":assurance if not failures else "NONE","package_id":manifest["package_id"],"evidence_checked":len(manifest["evidence"]),"checkpoint_id":checkpoint["checkpoint_id"],"failures":failures,"scope":"Selected raw bytes and envelopes, signed manifest, evidence chain commitments to checkpoint. Witness independence and freshness depend on how the trusted inputs were obtained."}
