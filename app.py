            entry["encrypted_title"].encode()
        ).decode()

        content = cipher.decrypt(
            entry["encrypted_content"].encode()
        ).decode()

    except InvalidToken:

        flash(
            "Unable to decrypt entry.",
            "error"
        )

        return redirect(
            url_for(
                "unlocked_diary",
                diary_id=diary_id
            )
        )

    entry_data = {
        "id": entry["id"],
        "title": title,
        "content": content,
        "created_at": entry["created_at"],
        "updated_at": entry["updated_at"]
    }

    return render_template(
        "entry.html",
        diary=diary,
        entry=entry_data
    )


@app.route(
    "/diary/<int:diary_id>/entry/<int:entry_id>/delete",
    methods=["GET", "POST"]
)
def delete_entry(
    diary_id,
    entry_id
):

    if not logged_in():
        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    key = get_unlock_key(
        diary_id
    )

    if not diary or not key:

        return redirect(
            url_for(
                "locked_diary",
                diary_id=diary_id
            )
        )

    execute(
        """
        DELETE FROM entries
        WHERE id = %s
        AND diary_id = %s
        """,
        (
            entry_id,
            diary_id
        )
    )

    flash(
        "Entry deleted.",
        "success"
    )

    return redirect(
        url_for(
            "unlocked_diary",
            diary_id=diary_id
        )
    )


@app.route(
    "/diary/<int:diary_id>/lock"
)
def lock_diary(diary_id):

    lock_current_diary()

    return redirect(
        url_for(
            "locked_diary",
            diary_id=diary_id
        )
    )


@app.route("/lock")
def lock():

    lock_current_diary()

    return redirect(
        url_for("dashboard")
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )
    
