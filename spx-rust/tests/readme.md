# Testing

To run the tests on an individual mode: 
```shell
cargo test --features "haraka f128 simple" --release  
```

To run a shorter subset (10 test vectors) use the env variable SPHINCS_FAST_TEST
```shell
SPHINCS_FAST_TEST=1 cargo test --features "haraka f128 simple" --release
```

it is recommended to run tests with release builds, even when using the subset.

To go through the full matrix of all modes use the [test_matrix.sh](./test_matrix.sh) file.