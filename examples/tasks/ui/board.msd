# The signed-in user's tasks, rendered on the server. Values are escaped automatically.
import tasks

@guard(tasks::me)
page GET "/" (state, auth) -> html:
    let tasks = tasks::tasks_of(state, &auth.sub).await?
    let open = tasks.iter().filter(|t| not t.done).count()
    html(lang="en"):
        head:
            meta(charset="utf-8")
            title Tasks
        body:
            main:
                h1 Tasks for {auth.name}
                p {open} open, {tasks.len()} total
                if tasks.is_empty():
                    p Nothing yet. POST /api/tasks to add one.
                else:
                    ul:
                        for t in &tasks:
                            let state_class = if t.done: "done" else: "open"
                            li(class="{state_class}") {t.title}
                form(method="post" action="/auth/logout"):
                    button(type="submit") Sign out
