#!/bin/bash

# Generate wrapped credentials for all test cases
# This script runs the credential generation scripts for each test case

set -e  # Exit on any error

echo "🚀 Regenerating all wrapped credentials..."
echo "==========================================="

# Change to the veramo-scripts directory where the .env file is located
cd tests/veramo-scripts

# Array of test cases and their script paths
declare -a test_cases=(
    "manifesto:src/manifesto/create-credential.ts"
    "grant-with-feedback:src/grant-with-feedback/create-credential.ts"
    "grant-simple:src/grant-simple/create-credential.ts"
    "mou:src/mou/create-credential.ts"
)

# Track results
successful=0
failed=0
failed_cases=()

# Run each test case
for case_info in "${test_cases[@]}"; do
    # Split the case_info into name and script path
    IFS=':' read -r case_name script_path <<< "$case_info"
    
    echo ""
    echo "📝 Generating wrapped credentials for: $case_name"
    echo "   Running: $script_path"
    
    if npx tsx "$script_path"; then
        echo "   ✅ $case_name - SUCCESS"
        ((successful++))
    else
        echo "   ❌ $case_name - FAILED"
        ((failed++))
        failed_cases+=("$case_name")
    fi
done

echo ""
echo "==========================================="
echo "📊 SUMMARY:"
echo "   Total test cases: $((successful + failed))"
echo "   Successful: $successful"
echo "   Failed: $failed"

if [ ${#failed_cases[@]} -gt 0 ]; then
    echo ""
    echo "❌ Failed test cases:"
    for case in "${failed_cases[@]}"; do
        echo "   - $case"
    done
    echo ""
    echo "💡 Make sure you have run 'npm install' in the veramo-scripts directory"
    echo "💡 Check that the .env file exists with proper configuration"
    exit 1
else
    echo ""
    echo "🎉 All wrapped credentials generated successfully!"
    echo "Ready to run tests with: ./run_tests.sh"
fi 