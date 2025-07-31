1. to run
    1. either this
        - `dx serve --package web`, `dx serve --package desktop`, `dx serve --package mobile`
    2. or this
        - `cd web && dx serve`, `cd web && dx desktop`, `cd web && dx mobile`
    3. 
        - `dx serve --package web --platform web`

    4. 
        -   `cargo run -p api`,`cargo run -p proxy`, `cargo leptos watch -p org`, `cargo leptos watch -p users`

 -- watch on `http://localhost:3000/`

 --- `https://www.youtube.com/watch?v=avG2W1-fyaE`
--- `https://www.shuttle.dev/blog/2022/08/11/authentication-tutorial#sessions`

2. ✅ Fix: Adjust permissions of the ./surreal_data folder
```bash
sudo mkdir -p ./surreal_data #create a parent folder `-p`
sudo chown -R 1000:1000 ./surreal_data
```

Note: `cargo-leptos watch --hot-reload` only works with the `nightly`

<!-- https://github.com/MikeCode00/Dioxus-Full-Stack-SQLite-To-Do-App/blob/main/Cargo.toml -->

- https://www.youtube.com/watch?v=w9rkil0dotI
- https://www.youtube.com/watch?v=DW9gNduZATE
- https://www.youtube.com/watch?v=itK6BSSe5DA
- https://www.youtube.com/watch?v=betxwPpX8Bw
