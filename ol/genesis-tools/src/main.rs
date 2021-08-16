use std::{path::PathBuf, process::exit};
use anyhow::Result;

use gumdrop::Options;
use ol_genesis_tools::{fork_genesis::make_recovery_genesis, swarm_genesis::make_swarm_genesis};


<<<<<<< HEAD
fn get_runtime() -> (Runtime, u16) {
    let port = get_available_port();
    let path = TempPath::new();
    let rt = start_backup_service(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), Arc::new(LibraDB::new_for_test(&path)));
    (rt, port)
}


async fn open_for_read(
    file_handle: &FileHandleRef,
) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
    let home = dirs::home_dir().unwrap();
    let mut path: String = home.join("libra/ol/fixtures/state-snapshot/194/").into_os_string().into_string().unwrap().to_owned();
    path.push_str(&file_handle.to_string());
    let file = OpenOptions::new().read(true).open(path).await?;
    Ok(Box::new(file))
}

fn read_from_file(path: &str) -> Result<Vec<u8>> {
    let mut data = Vec::<u8>::new();
    let mut f = File::open(path).expect("Unable to open file");
    f.read_to_end(&mut data).expect("Unable to read data");
    // println!("{}", data.len())?;
    Ok(data)
}

fn read_from_json(path: &str) -> Result<StateSnapshotBackup>{
    let config = std::fs::read_to_string(path)?;
    let map: StateSnapshotBackup = serde_json::from_str(&config)?;
    Ok(map)
}

fn load_lcs_file<T: DeserializeOwned>(file_handle: &str) -> Result<T> {
    let x = read_from_file(&file_handle)?;
    Ok(lcs::from_bytes(&x)?)
}

async fn read_account_state_chunk(file_handle: FileHandle) -> Result<Vec<(HashValue, AccountStateBlob)>> {
    let mut file = open_for_read(&file_handle).await?;

    let mut chunk = vec![];

    while let Some(record_bytes) = file.read_record_bytes().await? {
        chunk.push(lcs::from_bytes(&record_bytes)?);
    }
    Ok(chunk)
}

async fn run_impl(manifest: StateSnapshotBackup) -> Result<Vec<AccountStateBlob>> {
    let mut account_state_blobs: Vec<AccountStateBlob> = Vec::new();
    for chunk in manifest.chunks {
        
        let blobs = read_account_state_chunk(chunk.blobs).await?;
        // let proof = load_lcs_file(&chunk.proof)?;
        println!("{:?}", blobs);
        // TODO(Venkat) -> Here's the blob
        // println!("{:?}", proof);
        for (_key, blob) in blobs {
            account_state_blobs.push(blob)
        }

    }

    Ok(account_state_blobs)
}

pub fn get_account_state_blobs(path: PathBuf) -> Result<Vec<AccountStateBlob>> {
    let path_man = path.clone().join("state.manifest");
    dbg!(&path_man);
    let path_proof = path.join("state.proof");

    let manifest = read_from_json(&path_man.into_os_string().into_string().unwrap()).unwrap();

    let (mut rt, _port) = get_runtime();

    let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) = 
            load_lcs_file(&path_proof.into_os_string().into_string().unwrap()).unwrap();

    txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;

    ensure!(
        txn_info_with_proof.transaction_info().state_root_hash() == manifest.root_hash,
        "Root hash mismatch with that in proof. root hash: {}, expected: {}",
        manifest.root_hash,
        txn_info_with_proof.transaction_info().state_root_hash(),
    );

    // run_impl(manifest).unwrap()
    let future = run_impl(manifest); // Nothing is printed
    Ok(rt.block_on(future)?)
}

fn create_genesis_blob(path: PathBuf) -> Result<()>{
    
    let account_state_blobs = get_account_state_blobs(path).unwrap();
    
    let genesis = vm_genesis::test_genesis_change_set_and_validators(Some(1));
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis.0));
    let tmp_dir = TempPath::new();
    let db_rw = DbReaderWriter::new(LibraDB::new_for_test(&tmp_dir));

    // Executor won't be able to boot on empty db due to lack of StartupInfo.
    assert!(db_rw.reader.get_startup_info().unwrap().is_none());    

    // Bootstrap empty DB.
    let waypoint = generate_waypoint::<LibraVM>(&db_rw, &genesis_txn).expect("Should not fail.");
    maybe_bootstrap::<LibraVM>(&db_rw, &genesis_txn, waypoint).unwrap();
    let startup_info = db_rw
        .reader
        .get_startup_info()
        .expect("Should not fail.")
        .expect("Should not be None.");
    assert_eq!(
        Waypoint::new_epoch_boundary(startup_info.latest_ledger_info.ledger_info()).unwrap(),
        waypoint
    );
    let (li, epoch_change_proof, _) = db_rw.reader.get_state_proof(waypoint.version()).unwrap();
    let trusted_state = TrustedState::from(waypoint);
    trusted_state
        .verify_and_ratchet(&li, &epoch_change_proof)
        .unwrap();

    // `maybe_bootstrap()` does nothing on non-empty DB.
    assert!(!maybe_bootstrap::<LibraVM>(&db_rw, &genesis_txn, waypoint).unwrap());

    let genesis_txn = generate_genesis::generate_genesis_from_snapshot(&account_state_blobs, &db_rw).unwrap();
    generate_genesis::write_genesis_blob(genesis_txn)?;
    generate_genesis::verify_genesis_from_blob(&account_state_blobs, db_rw)?;
    println!("\nGenesis blob successfully generated from snapshot");
    Ok(())
}

fn main() -> Result<()>{
=======
#[tokio::main]
async fn main() -> Result<()> {
>>>>>>> f2acec2155bb955a2eecf42293adee83d46d550b
    #[derive(Debug, Options)]
    struct Args {
        #[options(help = "what epoch to restore from archive")]
        epoch: Option<u64>,
        #[options(help = "path to snapshot dir to read")]
        snapshot: Option<PathBuf>,
        #[options(help = "write genesis from snapshot")]
        genesis: Option<PathBuf>,
        #[options(help = "optional, write recovery file from snapshot")]
        recover: Option<PathBuf>,
        #[options(help = "optional, get baseline genesis without changes, for dubugging")]
        debug_baseline: bool,
        #[options(help = "live fork mode")]
        daemon: bool,
        #[options(help = "swarm simulation mode")]
        swarm: bool,
    }

    let opts = Args::parse_args_default_or_exit();

    if let Some(g_path) = opts.genesis {
      if let Some(s_path) = opts.snapshot {
        // create a genesis file from archive file
        make_recovery_genesis(g_path, s_path, true).await?;
        return Ok(())
      } else {
        println!("ERROR: must provide a path with --snapshot, exiting.");
        exit(1);
      }


    } else if let Some(_a_path) = opts.recover {
      // just create recovery file
        
        return Ok(())
    } else if opts.daemon {
        // start the live fork daemon

        return Ok(())
    } else if opts.swarm {
        // Write swarm genesis from snapshot, for CI and simulation
        if let Some(archive_path) = opts.snapshot {
          make_swarm_genesis(opts.genesis.unwrap(), archive_path).await?;
          return Ok(())
        } else {
        println!("ERROR: must provide a path with --snapshot, exiting.");
        exit(1);
      }
        
    } else {
        println!("ERROR: no options provided, exiting.");
        exit(1);
    }
}
