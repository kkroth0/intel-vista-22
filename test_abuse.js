
async function test() {
    try {
        const response = await fetch('http://localhost:3001/api/abuseipdb', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: '1.1.1.1' })
        });
        const data = await response.json();
        console.log("Top keys:", Object.keys(data));
        if (data.data) {
            console.log("data keys:", Object.keys(data.data));
            if (data.data.data) {
                console.log("data.data keys:", Object.keys(data.data.data));
                console.log("data.data:", JSON.stringify(data.data.data, null, 2));
            }
        }
    } catch (error) {
        console.error(error);
    }
}

test();
