
async function test() {
    try {
        const response = await fetch('http://localhost:3001/api/virustotal', {
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
                if (data.data.data.attributes) {
                    console.log("data.data.attributes keys:", Object.keys(data.data.data.attributes));
                }
            }
            if (data.data.attributes) {
                console.log("data.attributes keys:", Object.keys(data.data.attributes));
            }
        }
    } catch (error) {
        console.error(error);
    }
}

test();
