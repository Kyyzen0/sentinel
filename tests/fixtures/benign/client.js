// JavaScript sample - looks like a typical frontend helper.

export function fetchData(url) {
    return fetch(url)
        .then((response) => response.json())
        .catch((err) => console.error(err));
}

const greet = (name) => {
    return `Hello, ${name}!`;
};
