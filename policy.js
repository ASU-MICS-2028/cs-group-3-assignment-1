// Authorization policy: the single place that decides what a signed-in user may do.
// Every protected route calls one of these functions. Default is DENY:
// a function returns true only when a rule explicitly allows the request.
// "Who is asking" always comes from the server-side session, never from the request.

export function createPolicy(db) {
  const q = {
    teaches: db.prepare(
      'SELECT 1 FROM lecturer_courses WHERE lecturer_id = ? AND course_id = ?'),
    isEnrolled: db.prepare(
      'SELECT 1 FROM enrollments WHERE student_id = ? AND course_id = ?'),
    sharesCourse: db.prepare(
      `SELECT 1 FROM lecturer_courses lc
         JOIN enrollments e ON e.course_id = lc.course_id
        WHERE lc.lecturer_id = ? AND e.student_id = ? LIMIT 1`),
  };
  const teaches = (lecturerId, courseId) => q.teaches.get(lecturerId, courseId) !== undefined;
  const isEnrolled = (studentId, courseId) => q.isEnrolled.get(studentId, courseId) !== undefined;
  const sharesCourse = (lecturerId, studentId) => q.sharesCourse.get(lecturerId, studentId) !== undefined;

  // GET /students/:studentId
  function canReadStudent(user, studentId) {
    if (user.role === 'student') return user.id === studentId;            // own record only
    if (user.role === 'lecturer') return sharesCourse(user.id, studentId); // students in a course they teach
    return false;
  }

  // POST /courses/:courseId/grades/:studentId
  function canEditGrade(user, courseId, studentId) {
    return user.role === 'lecturer'
      && teaches(user.id, courseId)          // e.g. L001 teaches C101
      && isEnrolled(studentId, courseId);    // the student takes that course
  }

  // GET /courses/:courseId/roster
  function canViewRoster(user, courseId) {
    return user.role === 'lecturer' && teaches(user.id, courseId);
  }

  return { canReadStudent, canEditGrade, canViewRoster, teaches };
}
