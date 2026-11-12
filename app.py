
import os
import hmac
import secrets
from datetime import date, datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from database import get_connection
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "local-development-only-change-before-deploy"

BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]


# --------------------------------------------------
# COMMON HELPERS
# --------------------------------------------------

def login_required():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return None


def role_required(role):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != role:
        return "Access Denied!"

    return None


def create_notification(cursor, user_id, message):
    cursor.execute("""
        INSERT INTO notifications (user_id, message, is_read)
        VALUES (%s, %s, 0)
    """, (user_id, message))


# --------------------------------------------------
# UNREAD NOTIFICATION COUNT
# --------------------------------------------------

@app.context_processor
def inject_unread_count():
    unread_count = 0

    if "user_id" in session:
        connection = get_connection()

        if connection:
            cursor = connection.cursor()

            try:
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM notifications
                    WHERE user_id = %s AND is_read = 0
                """, (session["user_id"],))

                result = cursor.fetchone()
                unread_count = result[0] if result else 0

            except Exception:
                unread_count = 0

            finally:
                cursor.close()
                connection.close()

    return {"unread_notification_count": unread_count}


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role")

        if not name or not email or not phone or not password:
            return "Please fill in all required fields."

        if password != confirm_password:
            return "Passwords do not match!"

        if role not in ["user", "donor", "volunteer"]:
            return "Invalid registration role!"

        donor_blood_group = None
        donor_city = None
        donor_address = None
        volunteer_skills = request.form.get("skills", "").strip()
        volunteer_city = request.form.get("volunteer_city", "").strip()

        if role == "donor":
            donor_blood_group = request.form.get("blood_group")
            donor_city = request.form.get("city", "").strip()
            donor_address = request.form.get("address", "").strip()

            if donor_blood_group not in BLOOD_GROUPS:
                return "Please select a valid blood group."

            if not donor_city or not donor_address:
                return "Please enter all donor details."

        hashed_password = generate_password_hash(password)
        connection = get_connection()

        if connection is None:
            return "Database Connection Failed!"

        cursor = connection.cursor()

        try:
            cursor.execute("""
                INSERT INTO users
                (full_name, email, phone, password, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (name, email, phone, hashed_password, role))

            user_id = cursor.lastrowid

            if role == "donor":
                cursor.execute("""
                    INSERT INTO donors
                    (user_id, blood_group, city, address, available)
                    VALUES (%s, %s, %s, %s, 1)
                """, (
                    user_id,
                    donor_blood_group,
                    donor_city,
                    donor_address
                ))

            elif role == "volunteer":
                cursor.execute("""
                    INSERT INTO volunteers
                    (user_id, skills, city, availability)
                    VALUES (%s, %s, %s, 1)
                """, (
                    user_id,
                    volunteer_skills or None,
                    volunteer_city or None
                ))

            connection.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as error:
            connection.rollback()
            return "Registration Error: " + str(error)

        finally:
            cursor.close()
            connection.close()

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        connection = get_connection()

        if connection is None:
            return "Database Connection Failed!"

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()

        finally:
            cursor.close()
            connection.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["user_name"] = user["full_name"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        return "Invalid Email or Password!"

    return render_template("login.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():
    check = login_required()
    if check:
        return check

    role = session.get("role")

    if role == "user":
        return render_template("user_dashboard.html")

    if role == "donor":
        return render_template("donor_dashboard.html")

    if role == "volunteer":
        return render_template("volunteer_dashboard.html")

    if role == "admin":
        return render_template("admin_dashboard.html")

    return "Invalid User Role!"


# --------------------------------------------------
# ADMIN - MANAGE USERS
# --------------------------------------------------

@app.route("/admin/users")
def admin_users():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        # A one-session token protects the destructive POST action from CSRF.
        session["admin_users_csrf_token"] = secrets.token_urlsafe(32)

        cursor.execute("""
            SELECT user_id, full_name, email, phone, role, created_at
            FROM users
            ORDER BY user_id DESC
        """)

        users = cursor.fetchall()
        return render_template(
            "admin_users.html",
            users=users,
            csrf_token=session["admin_users_csrf_token"]
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - PERMANENTLY DELETE A USER ACCOUNT
# --------------------------------------------------

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    check = role_required("admin")
    if check:
        return check

    # Never allow an administrator to delete their own active account.
    if user_id == session.get("user_id"):
        flash("You cannot delete your own administrator account.", "error")
        return redirect(url_for("admin_users"))

    submitted_token = request.form.get("csrf_token", "")
    saved_token = session.get("admin_users_csrf_token", "")
    if not saved_token or not submitted_token or not hmac.compare_digest(
        submitted_token, saved_token
    ):
        flash("The delete request could not be verified. Please refresh the page and try again.", "error")
        return redirect(url_for("admin_users"))

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id, full_name, role FROM users WHERE user_id = %s",
            (user_id,)
        )
        target_user = cursor.fetchone()

        if not target_user:
            connection.rollback()
            flash("User not found. The user list may have changed.", "error")
            return redirect(url_for("admin_users"))

        # Keep administrator accounts protected from deletion through this page.
        if target_user["role"] == "admin":
            connection.rollback()
            flash("Administrator accounts cannot be deleted from Manage Users.", "error")
            return redirect(url_for("admin_users"))

        cursor.execute("SELECT donor_id FROM donors WHERE user_id = %s", (user_id,))
        donor_row = cursor.fetchone()
        donor_id = donor_row["donor_id"] if donor_row else None

        cursor.execute("SELECT volunteer_id FROM volunteers WHERE user_id = %s", (user_id,))
        volunteer_row = cursor.fetchone()
        volunteer_id = volunteer_row["volunteer_id"] if volunteer_row else None

        # Preserve other users' blood requests, but remove the deleted donor link.
        if donor_id is not None:
            cursor.execute(
                "UPDATE blood_requests SET accepted_donor_id = NULL WHERE accepted_donor_id = %s",
                (donor_id,)
            )

        # Remove acceptance rows associated with this user's requests or donor profile.
        cursor.execute("""
            DELETE FROM blood_request_acceptances
            WHERE request_id IN (SELECT request_id FROM blood_requests WHERE user_id = %s)
        """, (user_id,))
        if donor_id is not None:
            cursor.execute(
                "DELETE FROM blood_request_acceptances WHERE donor_id = %s",
                (donor_id,)
            )

        # Donation history has foreign keys to both donors and blood requests.
        if donor_id is not None:
            cursor.execute(
                "DELETE FROM donation_history WHERE donor_id = %s",
                (donor_id,)
            )
        cursor.execute("""
            DELETE FROM donation_history
            WHERE request_id IN (SELECT request_id FROM blood_requests WHERE user_id = %s)
        """, (user_id,))

        # Keep other requesters' volunteer requests, but unassign this volunteer.
        if volunteer_id is not None:
            cursor.execute("""
                UPDATE volunteer_requests
                SET volunteer_id = NULL
                WHERE volunteer_id = %s AND user_id <> %s
            """, (volunteer_id, user_id))

        # Remove requests and notifications owned by the account being deleted.
        cursor.execute("DELETE FROM volunteer_requests WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM blood_requests WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM notifications WHERE user_id = %s", (user_id,))

        if donor_id is not None:
            cursor.execute("DELETE FROM donors WHERE donor_id = %s", (donor_id,))
        if volunteer_id is not None:
            cursor.execute("DELETE FROM volunteers WHERE volunteer_id = %s", (volunteer_id,))

        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))

        if cursor.rowcount == 1:
            connection.commit()
            flash(
                "User account for " + target_user["full_name"] +
                " and its linked profile data were permanently deleted.",
                "success"
            )
        else:
            connection.rollback()
            flash("The user account was not deleted.", "error")

    except Exception:
        connection.rollback()
        app.logger.exception("Failed to delete user account user_id=%s", user_id)
        flash("Unable to delete this user. No changes were saved. Please check the application logs.", "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_users"))


# --------------------------------------------------
# ADMIN - MANAGE DONORS
# --------------------------------------------------

@app.route("/admin/donors")
def admin_donors():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                d.donor_id, d.user_id, u.full_name, u.email, u.phone,
                d.blood_group, d.city, d.address, d.available,
                d.last_donation_date
            FROM donors d
            INNER JOIN users u ON d.user_id = u.user_id
            ORDER BY d.donor_id DESC
        """)

        donors = cursor.fetchall()
        return render_template("admin_donors.html", donors=donors)

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - MANAGE VOLUNTEERS
# --------------------------------------------------

@app.route("/admin/volunteers")
def admin_volunteers():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                v.volunteer_id,
                v.user_id,
                u.full_name,
                u.email,
                u.phone,
                v.skills,
                v.city,
                v.availability,

                (
                    SELECT COUNT(*)
                    FROM volunteer_requests vr
                    WHERE vr.volunteer_id = v.volunteer_id
                ) AS total_tasks,

                (
                    SELECT COUNT(*)
                    FROM volunteer_requests vr
                    WHERE vr.volunteer_id = v.volunteer_id
                      AND vr.status = 'Accepted'
                ) AS active_tasks,

                (
                    SELECT COUNT(*)
                    FROM volunteer_requests vr
                    WHERE vr.volunteer_id = v.volunteer_id
                      AND vr.status = 'Completed'
                ) AS completed_tasks

            FROM volunteers v
            INNER JOIN users u ON v.user_id = u.user_id
            ORDER BY v.volunteer_id DESC
        """)

        volunteers = cursor.fetchall()

        return render_template(
            "admin_volunteers.html",
            volunteers=volunteers
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - UPDATE VOLUNTEER AVAILABILITY
# --------------------------------------------------

@app.route(
    "/admin/update-volunteer-availability/<int:volunteer_id>",
    methods=["POST"]
)
def admin_update_volunteer_availability(volunteer_id):
    check = role_required("admin")
    if check:
        return check

    new_status = request.form.get("availability")

    if new_status not in ["0", "1"]:
        flash("Invalid volunteer availability.", "error")
        return redirect(url_for("admin_volunteers"))

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        cursor.execute("""
            UPDATE volunteers
            SET availability = %s
            WHERE volunteer_id = %s
        """, (int(new_status), volunteer_id))

        if cursor.rowcount == 0:
            flash("Volunteer not found or availability unchanged.", "info")
        else:
            connection.commit()
            flash("Volunteer availability updated successfully.", "success")

        return redirect(url_for("admin_volunteers"))

    except Exception as error:
        connection.rollback()
        flash(
            "Unable to update volunteer availability: " + str(error),
            "error"
        )
        return redirect(url_for("admin_volunteers"))

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - DONATION CAMPS
# --------------------------------------------------

@app.route("/admin/donation-camps")
def admin_donation_camps():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT *
            FROM donation_camps
            ORDER BY camp_date DESC, start_time DESC
        """)

        camps = cursor.fetchall()

        return render_template(
            "admin_donation_camps.html",
            camps=camps,
            camp=None
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - ADD DONATION CAMP
# --------------------------------------------------

@app.route("/admin/donation-camps/add", methods=["POST"])
def admin_add_donation_camp():
    check = role_required("admin")
    if check:
        return check

    camp_name = request.form.get("camp_name", "").strip()
    organizer = request.form.get("organizer", "").strip()
    description = request.form.get("description", "").strip()
    venue = request.form.get("venue", "").strip()
    city = request.form.get("city", "").strip()
    camp_date_value = request.form.get("camp_date", "")
    start_time_value = request.form.get("start_time", "")
    end_time_value = request.form.get("end_time", "")
    contact_person = request.form.get("contact_person", "").strip()
    contact_phone = request.form.get("contact_phone", "").strip()

    if not all([
        camp_name,
        venue,
        city,
        camp_date_value,
        start_time_value,
        end_time_value
    ]):
        flash("Please fill in all required camp details.", "error")
        return redirect(url_for("admin_donation_camps"))

    try:
        camp_date = date.fromisoformat(camp_date_value)
        start_time = datetime.strptime(start_time_value, "%H:%M").time()
        end_time = datetime.strptime(end_time_value, "%H:%M").time()

        if camp_date < date.today():
            flash("Camp date cannot be in the past.", "error")
            return redirect(url_for("admin_donation_camps"))

        if end_time <= start_time:
            flash("End time must be later than start time.", "error")
            return redirect(url_for("admin_donation_camps"))

    except ValueError:
        flash("Please enter a valid camp date and time.", "error")
        return redirect(url_for("admin_donation_camps"))

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT INTO donation_camps (
                camp_name,
                organizer,
                description,
                venue,
                city,
                camp_date,
                start_time,
                end_time,
                contact_person,
                contact_phone,
                status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Upcoming')
        """, (
            camp_name,
            organizer or None,
            description or None,
            venue,
            city,
            camp_date,
            start_time,
            end_time,
            contact_person or None,
            contact_phone or None
        ))

        connection.commit()
        flash("Donation camp added successfully.", "success")

    except Exception as error:
        connection.rollback()
        flash("Unable to add donation camp: " + str(error), "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_donation_camps"))


# --------------------------------------------------
# ADMIN - EDIT DONATION CAMP
# --------------------------------------------------

@app.route(
    "/admin/donation-camps/edit/<int:camp_id>",
    methods=["GET", "POST"]
)
def admin_edit_donation_camp(camp_id):
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":
            camp_name = request.form.get("camp_name", "").strip()
            organizer = request.form.get("organizer", "").strip()
            description = request.form.get("description", "").strip()
            venue = request.form.get("venue", "").strip()
            city = request.form.get("city", "").strip()
            camp_date_value = request.form.get("camp_date", "")
            start_time_value = request.form.get("start_time", "")
            end_time_value = request.form.get("end_time", "")
            contact_person = request.form.get("contact_person", "").strip()
            contact_phone = request.form.get("contact_phone", "").strip()

            if not all([
                camp_name,
                venue,
                city,
                camp_date_value,
                start_time_value,
                end_time_value
            ]):
                flash("Please fill in all required camp details.", "error")
                return redirect(
                    url_for("admin_edit_donation_camp", camp_id=camp_id)
                )

            try:
                camp_date = date.fromisoformat(camp_date_value)
                start_time = datetime.strptime(
                    start_time_value, "%H:%M"
                ).time()
                end_time = datetime.strptime(
                    end_time_value, "%H:%M"
                ).time()

                if end_time <= start_time:
                    flash("End time must be later than start time.", "error")
                    return redirect(
                        url_for("admin_edit_donation_camp", camp_id=camp_id)
                    )

            except ValueError:
                flash("Please enter a valid camp date and time.", "error")
                return redirect(
                    url_for("admin_edit_donation_camp", camp_id=camp_id)
                )

            cursor.execute("""
                UPDATE donation_camps
                SET
                    camp_name = %s,
                    organizer = %s,
                    description = %s,
                    venue = %s,
                    city = %s,
                    camp_date = %s,
                    start_time = %s,
                    end_time = %s,
                    contact_person = %s,
                    contact_phone = %s
                WHERE camp_id = %s
            """, (
                camp_name,
                organizer or None,
                description or None,
                venue,
                city,
                camp_date,
                start_time,
                end_time,
                contact_person or None,
                contact_phone or None,
                camp_id
            ))

            if cursor.rowcount == 0:
                connection.rollback()
                flash("No camp was updated. It may not exist or details are unchanged.", "info")
            else:
                connection.commit()
                flash("Donation camp updated successfully.", "success")

            return redirect(url_for("admin_donation_camps"))

        cursor.execute("""
            SELECT *
            FROM donation_camps
            WHERE camp_id = %s
        """, (camp_id,))

        camp = cursor.fetchone()

        if camp is None:
            flash("Donation camp not found.", "error")
            return redirect(url_for("admin_donation_camps"))

        cursor.execute("""
            SELECT *
            FROM donation_camps
            ORDER BY camp_date DESC, start_time DESC
        """)

        camps = cursor.fetchall()

        return render_template(
            "admin_donation_camps.html",
            camps=camps,
            camp=camp
        )

    except Exception as error:
        connection.rollback()
        flash("Donation camp error: " + str(error), "error")
        return redirect(url_for("admin_donation_camps"))

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - CANCEL DONATION CAMP
# --------------------------------------------------

@app.route(
    "/admin/donation-camps/cancel/<int:camp_id>",
    methods=["POST"]
)
def admin_cancel_donation_camp(camp_id):
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        cursor.execute("""
            UPDATE donation_camps
            SET status = 'Cancelled'
            WHERE camp_id = %s
              AND status = 'Upcoming'
        """, (camp_id,))

        if cursor.rowcount == 1:
            connection.commit()
            flash("Donation camp cancelled successfully.", "success")
        else:
            connection.rollback()
            flash("Camp not found or it is not an upcoming camp.", "error")

    except Exception as error:
        connection.rollback()
        flash("Unable to cancel camp: " + str(error), "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_donation_camps"))


# --------------------------------------------------
# ADMIN - DELETE CANCELLED DONATION CAMP
# --------------------------------------------------

@app.route(
    "/admin/donation-camps/delete/<int:camp_id>",
    methods=["POST"]
)
def admin_delete_donation_camp(camp_id):
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        cursor.execute("""
            DELETE FROM donation_camps
            WHERE camp_id = %s
              AND status = 'Cancelled'
        """, (camp_id,))

        if cursor.rowcount == 1:
            connection.commit()
            flash("Cancelled donation camp deleted successfully.", "success")
        else:
            connection.rollback()
            flash("Only cancelled camps can be deleted.", "error")

    except Exception as error:
        connection.rollback()
        flash("Unable to delete camp: " + str(error), "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_donation_camps"))


# --------------------------------------------------
# USER / DONOR - VIEW UPCOMING DONATION CAMPS
# --------------------------------------------------

@app.route("/donation-camps")
def donation_camps():
    check = login_required()
    if check:
        return check

    connection = get_connection()

    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                camp_id,
                camp_name,
                organizer,
                description,
                venue,
                city,
                camp_date,
                start_time,
                end_time,
                contact_person,
                contact_phone,
                status
            FROM donation_camps
            WHERE status = 'Upcoming'
              AND camp_date >= CURDATE()
            ORDER BY camp_date ASC, start_time ASC
        """)

        camps = cursor.fetchall()

        return render_template(
            "donation_camps.html",
            camps=camps
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# USER - SUBMIT BLOOD REQUEST
# --------------------------------------------------

@app.route("/blood-request", methods=["GET", "POST"])
def blood_request():
    check = login_required()
    if check:
        return check

    if session.get("role") != "user":
        return "Only registered users can submit blood requests."

    if request.method == "POST":
        patient_name = request.form.get("patient_name", "").strip()
        blood_group = request.form.get("blood_group")
        units_required = request.form.get("units_required")
        hospital_name = request.form.get("hospital_name", "").strip()
        city = request.form.get("city", "").strip()
        urgency = request.form.get("urgency")
        required_date = request.form.get("required_date") or None

        allowed_urgencies = ["Normal", "Urgent", "Critical"]

        if not patient_name or not hospital_name or not city:
            return "Please fill in all required fields."

        if blood_group not in BLOOD_GROUPS:
            return "Please select a valid blood group."

        if urgency not in allowed_urgencies:
            return "Please select a valid urgency."

        try:
            units_required = int(units_required)

            if units_required < 1:
                return "Units required must be at least 1."

            if required_date:
                required_date = date.fromisoformat(required_date)

                if required_date < date.today():
                    return "Required date cannot be in the past."

        except (ValueError, TypeError):
            return "Please enter valid units and date."

        connection = get_connection()
        if connection is None:
            return "Database Connection Failed!"

        cursor = connection.cursor()

        try:
            cursor.execute("""
                INSERT INTO blood_requests
                (
                    user_id, patient_name, blood_group,
                    units_required, hospital_name, city,
                    urgency, required_date, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Pending')
            """, (
                session["user_id"],
                patient_name,
                blood_group,
                units_required,
                hospital_name,
                city,
                urgency,
                required_date
            ))

            request_id = cursor.lastrowid

            cursor.execute("""
                SELECT user_id
                FROM donors
                WHERE blood_group = %s
                  AND LOWER(TRIM(city)) = LOWER(TRIM(%s))
                  AND available = 1
            """, (blood_group, city))

            matching_donors = cursor.fetchall()

            message = (
                f"New {blood_group} blood request in {city}. "
                f"Patient: {patient_name}. "
                f"Hospital: {hospital_name}. "
                f"Units required: {units_required}. "
                f"Request ID: {request_id}."
            )

            for donor in matching_donors:
                create_notification(cursor, donor[0], message)

            connection.commit()

            flash("Blood request submitted successfully.", "success")

            if matching_donors:
                flash(
                    f"{len(matching_donors)} matching donor(s) have been notified.",
                    "success"
                )
            else:
                flash("No available matching donors were found in this city.", "info")

            return redirect(url_for("my_blood_requests"))

        except Exception as error:
            connection.rollback()
            return "Blood Request Error: " + str(error)

        finally:
            cursor.close()
            connection.close()

    return render_template("blood_request.html")


# --------------------------------------------------
# USER - VIEW OWN BLOOD REQUESTS
# --------------------------------------------------

@app.route("/my-blood-requests")
def my_blood_requests():
    check = role_required("user")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT *
            FROM blood_requests
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (session["user_id"],))

        requests_list = cursor.fetchall()

        return render_template(
            "my_blood_requests.html",
            requests_list=requests_list
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# DONOR - VIEW SMART MATCHING BLOOD REQUESTS
# --------------------------------------------------

@app.route("/donor/blood-requests")
def donor_blood_requests():
    check = role_required("donor")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT donor_id, blood_group, city, available
            FROM donors
            WHERE user_id = %s
        """, (session["user_id"],))

        donor = cursor.fetchone()

        if donor is None:
            return "Donor profile not found. Please contact the administrator."

        if donor["available"]:
            cursor.execute("""
                SELECT
                    br.request_id, br.patient_name, br.blood_group,
                    br.units_required, br.hospital_name, br.city,
                    br.urgency, br.required_date, br.status,
                    br.created_at, br.accepted_donor_id,
                    CASE
                        WHEN br.accepted_donor_id = %s THEN 1
                        ELSE 0
                    END AS accepted_by_me
                FROM blood_requests br
                WHERE br.blood_group = %s
                  AND LOWER(TRIM(br.city)) = LOWER(TRIM(%s))
                  AND (
                        br.status = 'Pending'
                        OR br.accepted_donor_id = %s
                  )
                ORDER BY
                    CASE br.urgency
                        WHEN 'Critical' THEN 1
                        WHEN 'Urgent' THEN 2
                        ELSE 3
                    END,
                    br.created_at DESC
            """, (
                donor["donor_id"],
                donor["blood_group"],
                donor["city"],
                donor["donor_id"]
            ))
        else:
            cursor.execute("""
                SELECT
                    br.request_id, br.patient_name, br.blood_group,
                    br.units_required, br.hospital_name, br.city,
                    br.urgency, br.required_date, br.status,
                    br.created_at, br.accepted_donor_id,
                    1 AS accepted_by_me
                FROM blood_requests br
                WHERE br.accepted_donor_id = %s
                ORDER BY br.created_at DESC
            """, (donor["donor_id"],))

        requests_list = cursor.fetchall()

        return render_template(
            "donor_blood_requests.html",
            requests_list=requests_list,
            donor=donor
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# DONOR - ACCEPT BLOOD REQUEST
# --------------------------------------------------

@app.route("/donor/accept-request/<int:request_id>", methods=["POST"])
def donor_accept_request(request_id):
    check = role_required("donor")
    if check:
        flash("Only donors can accept blood requests.", "error")
        return redirect(url_for("login"))

    connection = get_connection()
    if connection is None:
        flash("Database connection failed.", "error")
        return redirect(url_for("donor_blood_requests"))

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT donor_id, blood_group, city, available
            FROM donors
            WHERE user_id = %s
        """, (session["user_id"],))

        donor = cursor.fetchone()

        if donor is None:
            flash("Your donor profile was not found.", "error")
            return redirect(url_for("dashboard"))

        if not donor["available"]:
            flash("You are currently unavailable for donation.", "error")
            return redirect(url_for("donor_blood_requests"))

        cursor.execute("""
            UPDATE blood_requests
            SET
                accepted_donor_id = %s,
                accepted_at = CURRENT_TIMESTAMP,
                status = 'Matched'
            WHERE request_id = %s
              AND blood_group = %s
              AND LOWER(TRIM(city)) = LOWER(TRIM(%s))
              AND status = 'Pending'
              AND accepted_donor_id IS NULL
        """, (
            donor["donor_id"],
            request_id,
            donor["blood_group"],
            donor["city"]
        ))

        if cursor.rowcount == 1:
            cursor.execute("""
                SELECT user_id, patient_name
                FROM blood_requests
                WHERE request_id = %s
            """, (request_id,))

            request_record = cursor.fetchone()

            if request_record:
                message = (
                    f"Good news! Donor {session.get('user_name')} "
                    f"has accepted your blood request "
                    f"(Request ID: {request_id}) for "
                    f"{request_record['patient_name']}."
                )

                create_notification(
                    cursor,
                    request_record["user_id"],
                    message
                )

            connection.commit()
            flash("Blood request accepted successfully!", "success")

        else:
            connection.rollback()
            flash(
                "This request is no longer available. It may already have been accepted or may not match your city and blood group.",
                "error"
            )

        return redirect(url_for("donor_blood_requests"))

    except Exception as error:
        connection.rollback()
        flash("Unable to accept request: " + str(error), "error")
        return redirect(url_for("donor_blood_requests"))

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# DONOR PROFILE
# --------------------------------------------------

@app.route("/donor/profile", methods=["GET", "POST"])
def donor_profile():
    check = role_required("donor")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            blood_group = request.form.get("blood_group")
            city = request.form.get("city", "").strip()
            address = request.form.get("address", "").strip()

            if not all([full_name, email, phone, city, address]):
                flash("Please fill in all profile fields.", "error")
            elif blood_group not in BLOOD_GROUPS:
                flash("Please select a valid blood group.", "error")
            else:
                cursor.execute("""
                    SELECT user_id
                    FROM users
                    WHERE email = %s AND user_id != %s
                """, (email, session["user_id"]))

                existing_email = cursor.fetchone()

                if existing_email:
                    flash("This email address is already used by another account.", "error")
                else:
                    cursor.execute("""
                        UPDATE users
                        SET full_name = %s, email = %s, phone = %s
                        WHERE user_id = %s
                    """, (
                        full_name, email, phone, session["user_id"]
                    ))

                    cursor.execute("""
                        UPDATE donors
                        SET blood_group = %s, city = %s, address = %s
                        WHERE user_id = %s
                    """, (
                        blood_group, city, address, session["user_id"]
                    ))

                    connection.commit()
                    session["user_name"] = full_name
                    flash("Donor profile updated successfully.", "success")

            return redirect(url_for("donor_profile"))

        cursor.execute("""
            SELECT
                u.full_name, u.email, u.phone,
                d.donor_id, d.blood_group, d.city,
                d.address, d.available, d.last_donation_date
            FROM users u
            INNER JOIN donors d ON u.user_id = d.user_id
            WHERE u.user_id = %s
        """, (session["user_id"],))

        donor = cursor.fetchone()

        if donor is None:
            return "Donor profile not found."

        return render_template(
            "donor_profile.html",
            donor=donor,
            blood_groups=BLOOD_GROUPS
        )

    except Exception as error:
        connection.rollback()
        return "Profile Error: " + str(error)

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# DONOR AVAILABILITY
# --------------------------------------------------

@app.route("/donor/availability", methods=["GET", "POST"])
def donor_availability():
    check = role_required("donor")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":
            new_status = request.form.get("available")

            if new_status not in ["0", "1"]:
                flash("Invalid availability selection.", "error")
            else:
                cursor.execute("""
                    UPDATE donors
                    SET available = %s
                    WHERE user_id = %s
                """, (int(new_status), session["user_id"]))

                connection.commit()
                flash("Availability updated successfully.", "success")

            return redirect(url_for("donor_availability"))

        cursor.execute("""
            SELECT available
            FROM donors
            WHERE user_id = %s
        """, (session["user_id"],))

        donor = cursor.fetchone()

        if donor is None:
            return "Donor profile not found."

        return render_template("donor_availability.html", donor=donor)

    except Exception as error:
        connection.rollback()
        return "Availability Error: " + str(error)

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# DONOR ACCEPTED REQUEST HISTORY
# --------------------------------------------------

@app.route("/donor/accepted-requests")
def donor_accepted_requests():
    check = role_required("donor")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                br.request_id, br.patient_name, br.blood_group,
                br.units_required, br.hospital_name, br.city,
                br.urgency, br.required_date, br.status, br.accepted_at
            FROM blood_requests br
            INNER JOIN donors d ON br.accepted_donor_id = d.donor_id
            WHERE d.user_id = %s
            ORDER BY br.accepted_at DESC
        """, (session["user_id"],))

        requests_list = cursor.fetchall()

        return render_template(
            "donor_accepted_requests.html",
            requests_list=requests_list
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# DONOR DONATION HISTORY
# --------------------------------------------------

@app.route("/donor/donation-history")
def donor_donation_history():
    check = role_required("donor")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                dh.donation_id, dh.request_id, dh.donation_date,
                dh.hospital_name, dh.units_donated, dh.notes,
                br.patient_name, br.blood_group
            FROM donation_history dh
            INNER JOIN donors d ON dh.donor_id = d.donor_id
            LEFT JOIN blood_requests br ON dh.request_id = br.request_id
            WHERE d.user_id = %s
            ORDER BY dh.donation_date DESC, dh.donation_id DESC
        """, (session["user_id"],))

        donations = cursor.fetchall()

        return render_template(
            "donor_donation_history.html",
            donations=donations
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - VIEW AND RECORD DONATIONS
# --------------------------------------------------

@app.route("/admin/donations")
def admin_donations():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                br.request_id, br.patient_name, br.blood_group,
                br.units_required, br.hospital_name, br.city,
                br.required_date, br.status, br.accepted_at,
                d.donor_id, d.blood_group AS donor_blood_group,
                u.full_name AS donor_name, u.phone AS donor_phone
            FROM blood_requests br
            INNER JOIN donors d ON br.accepted_donor_id = d.donor_id
            INNER JOIN users u ON d.user_id = u.user_id
            WHERE br.status = 'Matched'
              AND NOT EXISTS (
                    SELECT 1
                    FROM donation_history dh
                    WHERE dh.request_id = br.request_id
              )
            ORDER BY br.accepted_at DESC
        """)

        matched_requests = cursor.fetchall()

        cursor.execute("""
            SELECT
                dh.donation_id, dh.request_id, dh.donation_date,
                dh.hospital_name, dh.units_donated,
                u.full_name AS donor_name, br.patient_name
            FROM donation_history dh
            INNER JOIN donors d ON dh.donor_id = d.donor_id
            INNER JOIN users u ON d.user_id = u.user_id
            LEFT JOIN blood_requests br ON dh.request_id = br.request_id
            ORDER BY dh.created_at DESC
        """)

        donations = cursor.fetchall()

        return render_template(
            "admin_donations.html",
            matched_requests=matched_requests,
            donations=donations
        )

    finally:
        cursor.close()
        connection.close()


@app.route("/admin/record-donation/<int:request_id>", methods=["POST"])
def admin_record_donation(request_id):
    check = role_required("admin")
    if check:
        return check

    donation_date = request.form.get("donation_date")
    units_donated = request.form.get("units_donated")
    notes = request.form.get("notes", "").strip()

    try:
        donation_date = date.fromisoformat(donation_date)
        units_donated = int(units_donated)

        if units_donated < 1:
            raise ValueError

    except (ValueError, TypeError):
        flash("Enter a valid donation date and units donated.", "error")
        return redirect(url_for("admin_donations"))

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                br.request_id, br.hospital_name, br.status,
                br.accepted_donor_id, d.donor_id
            FROM blood_requests br
            INNER JOIN donors d ON br.accepted_donor_id = d.donor_id
            WHERE br.request_id = %s
            FOR UPDATE
        """, (request_id,))

        blood_request_record = cursor.fetchone()

        if (
            blood_request_record is None
            or blood_request_record["status"] != "Matched"
            or blood_request_record["accepted_donor_id"] is None
        ):
            connection.rollback()
            flash("This request is not available for donation confirmation.", "error")
            return redirect(url_for("admin_donations"))

        cursor.execute("""
            INSERT INTO donation_history
            (
                donor_id, request_id, donation_date,
                hospital_name, units_donated, notes
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            blood_request_record["donor_id"],
            request_id,
            donation_date,
            blood_request_record["hospital_name"],
            units_donated,
            notes or None
        ))

        cursor.execute("""
            UPDATE blood_requests
            SET status = 'Completed'
            WHERE request_id = %s AND status = 'Matched'
        """, (request_id,))

        if cursor.rowcount != 1:
            raise Exception("The request status could not be updated.")

        cursor.execute("""
            UPDATE donors
            SET last_donation_date = %s
            WHERE donor_id = %s
        """, (donation_date, blood_request_record["donor_id"]))

        connection.commit()
        flash("Donation recorded and blood request marked Completed.", "success")

    except Exception as error:
        connection.rollback()
        flash("Unable to record donation: " + str(error), "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_donations"))


# --------------------------------------------------
# ADMIN - VIEW ALL BLOOD REQUESTS
# --------------------------------------------------

@app.route("/admin/blood-requests")
def admin_blood_requests():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                br.*,
                u.full_name AS requester_name,
                u.email AS requester_email,
                u.phone AS requester_phone
            FROM blood_requests br
            INNER JOIN users u ON br.user_id = u.user_id
            ORDER BY br.created_at DESC
        """)

        requests_list = cursor.fetchall()

        return render_template(
            "admin_blood_requests.html",
            requests_list=requests_list
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# ADMIN - UPDATE BLOOD REQUEST STATUS
# --------------------------------------------------

@app.route("/admin/update-blood-request/<int:request_id>", methods=["POST"])
def update_blood_request_status(request_id):
    check = role_required("admin")
    if check:
        return check

    new_status = request.form.get("status")
    allowed_statuses = ["Pending", "Matched", "Completed", "Cancelled"]

    if new_status not in allowed_statuses:
        return "Invalid request status."

    if new_status == "Completed":
        flash(
            "Use Admin Donations to confirm a real donation and complete this request.",
            "error"
        )
        return redirect(url_for("admin_donations"))

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        if new_status == "Pending":
            cursor.execute("""
                UPDATE blood_requests
                SET
                    status = %s,
                    accepted_donor_id = NULL,
                    accepted_at = NULL
                WHERE request_id = %s
            """, (new_status, request_id))
        else:
            cursor.execute("""
                UPDATE blood_requests
                SET status = %s
                WHERE request_id = %s
            """, (new_status, request_id))

        connection.commit()
        flash("Blood request status updated.", "success")
        return redirect(url_for("admin_blood_requests"))

    except Exception as error:
        connection.rollback()
        return "Status Update Error: " + str(error)

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# USER/DONOR NOTIFICATION HISTORY
# --------------------------------------------------

@app.route("/notifications")
def notifications():
    check = login_required()
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT notification_id, message, is_read, created_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY created_at DESC, notification_id DESC
        """, (session["user_id"],))

        notifications_list = cursor.fetchall()

        unread_count = sum(
            1 for item in notifications_list if not item["is_read"]
        )

        return render_template(
            "notifications.html",
            notifications=notifications_list,
            unread_count=unread_count
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# MARK ONE NOTIFICATION AS READ
# --------------------------------------------------

@app.route("/notifications/mark-read/<int:notification_id>", methods=["POST"])
def mark_notification_read(notification_id):
    check = login_required()
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        cursor.execute("""
            UPDATE notifications
            SET is_read = 1
            WHERE notification_id = %s
              AND user_id = %s
        """, (notification_id, session["user_id"]))

        connection.commit()
        flash("Notification marked as read.", "success")

    except Exception as error:
        connection.rollback()
        flash("Unable to update notification: " + str(error), "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("notifications"))


# --------------------------------------------------
# MARK ALL NOTIFICATIONS AS READ
# --------------------------------------------------

@app.route("/notifications/mark-all-read", methods=["POST"])
def mark_all_notifications_read():
    check = login_required()
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor()

    try:
        cursor.execute("""
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = %s AND is_read = 0
        """, (session["user_id"],))

        connection.commit()
        flash("All notifications marked as read.", "success")

    except Exception as error:
        connection.rollback()
        flash("Unable to update notifications: " + str(error), "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("notifications"))


# --------------------------------------------------
# ADMIN - NOTIFICATION HISTORY
# --------------------------------------------------

@app.route("/admin/notifications")
def admin_notifications():
    check = role_required("admin")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                n.notification_id,
                n.user_id,
                u.full_name,
                u.email,
                u.role,
                n.message,
                n.is_read,
                n.created_at
            FROM notifications n
            INNER JOIN users u ON n.user_id = u.user_id
            ORDER BY n.created_at DESC, n.notification_id DESC
        """)

        notifications_list = cursor.fetchall()

        cursor.execute("""
            SELECT
                COUNT(*) AS total_notifications,
                COALESCE(SUM(is_read = 0), 0) AS unread_notifications,
                COALESCE(SUM(is_read = 1), 0) AS read_notifications
            FROM notifications
        """)

        counts = cursor.fetchone()

        return render_template(
            "admin_notifications.html",
            notifications=notifications_list,
            counts=counts
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# VOLUNTEER - MANAGE PROFILE
# --------------------------------------------------

@app.route("/volunteer/profile", methods=["GET", "POST"])
def volunteer_profile():
    check = role_required("volunteer")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            skills = request.form.get("skills", "").strip()
            city = request.form.get("city", "").strip()

            if not all([full_name, email, phone, city]):
                flash("Please enter your name, email, phone and city.", "error")
                return redirect(url_for("volunteer_profile"))

            cursor.execute("""
                SELECT user_id FROM users
                WHERE email = %s AND user_id != %s
            """, (email, session["user_id"]))

            if cursor.fetchone():
                flash("This email address is already used by another account.", "error")
                return redirect(url_for("volunteer_profile"))

            cursor.execute("""
                UPDATE users
                SET full_name = %s, email = %s, phone = %s
                WHERE user_id = %s
            """, (full_name, email, phone, session["user_id"]))

            cursor.execute("""
                UPDATE volunteers
                SET skills = %s, city = %s
                WHERE user_id = %s
            """, (skills or None, city, session["user_id"]))

            connection.commit()
            session["user_name"] = full_name
            flash("Volunteer profile updated successfully.", "success")
            return redirect(url_for("volunteer_profile"))

        cursor.execute("""
            SELECT u.full_name, u.email, u.phone,
                   v.volunteer_id, v.skills, v.city, v.availability
            FROM users u
            INNER JOIN volunteers v ON u.user_id = v.user_id
            WHERE u.user_id = %s
        """, (session["user_id"],))

        volunteer = cursor.fetchone()

        if volunteer is None:
            return "Volunteer profile not found. Please contact the administrator."

        return render_template("volunteer_profile.html", volunteer=volunteer)

    except Exception as error:
        connection.rollback()
        return "Volunteer Profile Error: " + str(error)

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# VOLUNTEER - VIEW AVAILABLE EMERGENCY ACTIVITIES
# --------------------------------------------------

@app.route("/volunteer/emergency-activities")
def volunteer_emergency_activities():
    check = role_required("volunteer")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT emergency_id, user_id, volunteer_id, emergency_type,
                   description, location, status, created_at
            FROM volunteer_requests
            WHERE status = 'Pending'
               OR volunteer_id = (
                    SELECT volunteer_id FROM volunteers WHERE user_id = %s
               )
            ORDER BY created_at DESC, emergency_id DESC
        """, (session["user_id"],))

        activities = cursor.fetchall()

        return render_template(
            "volunteer_emergency_activities.html",
            activities=activities
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# VOLUNTEER - ACCEPT AN EMERGENCY ACTIVITY
# --------------------------------------------------

@app.route("/volunteer/accept-emergency/<int:emergency_id>", methods=["POST"])
def volunteer_accept_emergency(emergency_id):
    check = role_required("volunteer")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        flash("Database connection failed.", "error")
        return redirect(url_for("volunteer_emergency_activities"))

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT volunteer_id FROM volunteers WHERE user_id = %s",
            (session["user_id"],)
        )

        volunteer = cursor.fetchone()

        if volunteer is None:
            flash("Volunteer profile not found.", "error")
            return redirect(url_for("dashboard"))

        cursor.execute("""
            UPDATE volunteer_requests
            SET volunteer_id = %s, status = 'Accepted'
            WHERE emergency_id = %s AND status = 'Pending'
              AND volunteer_id IS NULL
        """, (volunteer["volunteer_id"], emergency_id))

        if cursor.rowcount == 1:
            cursor.execute("""
                SELECT user_id, emergency_type
                FROM volunteer_requests
                WHERE emergency_id = %s
            """, (emergency_id,))

            activity = cursor.fetchone()

            if activity:
                create_notification(
                    cursor,
                    activity["user_id"],
                    f"Your emergency request '{activity['emergency_type']}' has been accepted by {session.get('user_name')}."
                )

            connection.commit()
            flash("Emergency activity accepted successfully.", "success")

        else:
            connection.rollback()
            flash("This activity is no longer available.", "error")

        return redirect(url_for("volunteer_emergency_activities"))

    except Exception as error:
        connection.rollback()
        flash("Unable to accept activity: " + str(error), "error")
        return redirect(url_for("volunteer_emergency_activities"))

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# VOLUNTEER - VIEW ASSIGNED TASKS
# --------------------------------------------------

@app.route("/volunteer/tasks")
def volunteer_tasks():
    check = role_required("volunteer")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT emergency_id, emergency_type, description, location,
                   status, created_at
            FROM volunteer_requests
            WHERE volunteer_id = (
                SELECT volunteer_id FROM volunteers WHERE user_id = %s
            )
            ORDER BY created_at DESC, emergency_id DESC
        """, (session["user_id"],))

        tasks = cursor.fetchall()

        return render_template("volunteer_tasks.html", tasks=tasks)

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# VOLUNTEER - MARK ASSIGNED TASK AS COMPLETED
# --------------------------------------------------

@app.route("/volunteer/complete-task/<int:emergency_id>", methods=["POST"])
def volunteer_complete_task(emergency_id):
    check = role_required("volunteer")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        flash("Database connection failed.", "error")
        return redirect(url_for("volunteer_tasks"))

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            UPDATE volunteer_requests
            SET status = 'Completed'
            WHERE emergency_id = %s
              AND volunteer_id = (
                  SELECT volunteer_id FROM volunteers WHERE user_id = %s
              )
              AND status = 'Accepted'
        """, (emergency_id, session["user_id"]))

        if cursor.rowcount == 1:
            cursor.execute("""
                SELECT user_id, emergency_type
                FROM volunteer_requests
                WHERE emergency_id = %s
            """, (emergency_id,))

            activity = cursor.fetchone()

            if activity:
                create_notification(
                    cursor,
                    activity["user_id"],
                    f"Your emergency request '{activity['emergency_type']}' has been marked completed."
                )

            connection.commit()
            flash("Task marked as completed.", "success")

        else:
            connection.rollback()
            flash(
                "Task could not be completed. Check that it is assigned to you and still accepted.",
                "error"
            )

        return redirect(url_for("volunteer_tasks"))

    except Exception as error:
        connection.rollback()
        flash("Unable to update task: " + str(error), "error")
        return redirect(url_for("volunteer_tasks"))

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# VOLUNTEER - VIEW CONTRIBUTIONS
# --------------------------------------------------

@app.route("/volunteer/contributions")
def volunteer_contributions():
    check = role_required("volunteer")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT COUNT(*) AS total_tasks,
                   COALESCE(SUM(status = 'Completed'), 0) AS completed_tasks,
                   COALESCE(SUM(status = 'Accepted'), 0) AS active_tasks
            FROM volunteer_requests
            WHERE volunteer_id = (
                SELECT volunteer_id FROM volunteers WHERE user_id = %s
            )
        """, (session["user_id"],))

        contributions = cursor.fetchone()

        return render_template(
            "volunteer_contributions.html",
            contributions=contributions
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# USER - SUBMIT AN EMERGENCY VOLUNTEER REQUEST
# --------------------------------------------------

@app.route("/volunteer-request", methods=["GET", "POST"])
def submit_volunteer_request():
    check = role_required("user")
    if check:
        return check

    if request.method == "POST":
        emergency_type = request.form.get("emergency_type", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()

        if not emergency_type or not description or not location:
            flash("Please complete all fields before submitting.", "error")
            return redirect(url_for("submit_volunteer_request"))

        connection = get_connection()
        if connection is None:
            return "Database Connection Failed!"

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("""
                INSERT INTO volunteer_requests
                    (user_id, emergency_type, description, location, status)
                VALUES (%s, %s, %s, %s, 'Pending')
            """, (
                session["user_id"],
                emergency_type,
                description,
                location
            ))

            cursor.execute("""
                SELECT user_id
                FROM volunteers
                WHERE availability = 1
            """)

            available_volunteers = cursor.fetchall()

            for volunteer in available_volunteers:
                create_notification(
                    cursor,
                    volunteer["user_id"],
                    f"New emergency volunteer request: {emergency_type} at {location}."
                )

            connection.commit()
            flash("Your emergency volunteer request was submitted successfully.", "success")
            return redirect(url_for("my_volunteer_requests"))

        except Exception as error:
            connection.rollback()
            flash("Unable to submit your request: " + str(error), "error")
            return redirect(url_for("submit_volunteer_request"))

        finally:
            cursor.close()
            connection.close()

    return render_template("volunteer_request.html")


# --------------------------------------------------
# USER - VIEW OWN EMERGENCY VOLUNTEER REQUESTS
# --------------------------------------------------

@app.route("/my-volunteer-requests")
def my_volunteer_requests():
    check = role_required("user")
    if check:
        return check

    connection = get_connection()
    if connection is None:
        return "Database Connection Failed!"

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                vr.emergency_id,
                vr.emergency_type,
                vr.description,
                vr.location,
                vr.status,
                vr.created_at,
                assigned_user.full_name AS volunteer_name,
                assigned_user.phone AS volunteer_phone
            FROM volunteer_requests vr
            LEFT JOIN volunteers v
                ON vr.volunteer_id = v.volunteer_id
            LEFT JOIN users assigned_user
                ON v.user_id = assigned_user.user_id
            WHERE vr.user_id = %s
            ORDER BY vr.created_at DESC, vr.emergency_id DESC
        """, (session["user_id"],))

        requests_list = cursor.fetchall()

        return render_template(
            "my_volunteer_requests.html",
            requests_list=requests_list
        )

    finally:
        cursor.close()
        connection.close()


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
